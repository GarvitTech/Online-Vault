-- ============================================================
-- MY CLOUD DRIVE - SUPABASE DATABASE + SECURITY
-- Run this entire file in Supabase SQL Editor.
-- ============================================================

create extension if not exists pgcrypto;

-- ------------------------------------------------------------
-- PROFILES
-- ------------------------------------------------------------

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own"
on public.profiles
for select
to authenticated
using (id = auth.uid());

drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own"
on public.profiles
for update
to authenticated
using (id = auth.uid())
with check (id = auth.uid());

-- Create a profile automatically after signup.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, display_name)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email, '@', 1))
  )
  on conflict (id) do nothing;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- ------------------------------------------------------------
-- FOLDERS
-- ------------------------------------------------------------

create table if not exists public.folders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  parent_id uuid references public.folders(id) on delete cascade,
  name text not null,
  created_at timestamptz not null default now(),

  constraint folders_name_not_blank check (length(trim(name)) > 0),
  constraint folders_name_length check (length(name) <= 255)
);

create index if not exists folders_user_parent_idx
on public.folders(user_id, parent_id);

alter table public.folders enable row level security;

drop policy if exists "folders_select_own" on public.folders;
create policy "folders_select_own"
on public.folders
for select
to authenticated
using (user_id = auth.uid());

drop policy if exists "folders_insert_own" on public.folders;
create policy "folders_insert_own"
on public.folders
for insert
to authenticated
with check (user_id = auth.uid());

drop policy if exists "folders_update_own" on public.folders;
create policy "folders_update_own"
on public.folders
for update
to authenticated
using (user_id = auth.uid())
with check (user_id = auth.uid());

drop policy if exists "folders_delete_own" on public.folders;
create policy "folders_delete_own"
on public.folders
for delete
to authenticated
using (user_id = auth.uid());

-- ------------------------------------------------------------
-- FILE METADATA
-- Actual bytes live in private Storage.
-- ------------------------------------------------------------

create table if not exists public.files (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  folder_id uuid not null references public.folders(id) on delete cascade,
  name text not null,
  storage_path text not null unique,
  mime_type text not null default 'application/octet-stream',
  size_bytes bigint not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  constraint files_name_not_blank check (length(trim(name)) > 0),
  constraint files_name_length check (length(name) <= 255),
  constraint files_size_nonnegative check (size_bytes >= 0)
);

create index if not exists files_user_folder_idx
on public.files(user_id, folder_id);

create index if not exists files_user_name_idx
on public.files(user_id, lower(name));

alter table public.files enable row level security;

drop policy if exists "files_select_own" on public.files;
create policy "files_select_own"
on public.files
for select
to authenticated
using (user_id = auth.uid());

drop policy if exists "files_insert_own" on public.files;
create policy "files_insert_own"
on public.files
for insert
to authenticated
with check (user_id = auth.uid());

drop policy if exists "files_update_own" on public.files;
create policy "files_update_own"
on public.files
for update
to authenticated
using (user_id = auth.uid())
with check (user_id = auth.uid());

drop policy if exists "files_delete_own" on public.files;
create policy "files_delete_own"
on public.files
for delete
to authenticated
using (user_id = auth.uid());

-- ------------------------------------------------------------
-- UPDATED_AT TRIGGER
-- ------------------------------------------------------------

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists files_set_updated_at on public.files;
create trigger files_set_updated_at
before update on public.files
for each row execute procedure public.set_updated_at();

-- ------------------------------------------------------------
-- ROOT FOLDER
-- One root folder per user.
-- ------------------------------------------------------------

create or replace function public.ensure_root_folder()
returns uuid
language plpgsql
security invoker
as $$
declare
  root_id uuid;
begin
  select id into root_id
  from public.folders
  where user_id = auth.uid() and parent_id is null
  order by created_at
  limit 1;

  if root_id is null then
    insert into public.folders(user_id, parent_id, name)
    values(auth.uid(), null, 'My Drive')
    returning id into root_id;
  end if;

  return root_id;
end;
$$;

grant execute on function public.ensure_root_folder() to authenticated;

-- ------------------------------------------------------------
-- STORAGE BUCKET
-- ------------------------------------------------------------

insert into storage.buckets (id, name, public)
values ('vault', 'vault', false)
on conflict (id) do update set public = false;

-- Storage object path format:
-- <auth.uid>/<folder_id>/<file_id>
--
-- The first path segment MUST equal auth.uid().

drop policy if exists "vault_select_own" on storage.objects;
create policy "vault_select_own"
on storage.objects
for select
to authenticated
using (
  bucket_id = 'vault'
  and (storage.foldername(name))[1] = (select auth.uid()::text)
);

drop policy if exists "vault_insert_own" on storage.objects;
create policy "vault_insert_own"
on storage.objects
for insert
to authenticated
with check (
  bucket_id = 'vault'
  and (storage.foldername(name))[1] = (select auth.uid()::text)
);

drop policy if exists "vault_update_own" on storage.objects;
create policy "vault_update_own"
on storage.objects
for update
to authenticated
using (
  bucket_id = 'vault'
  and (storage.foldername(name))[1] = (select auth.uid()::text)
)
with check (
  bucket_id = 'vault'
  and (storage.foldername(name))[1] = (select auth.uid()::text)
);

drop policy if exists "vault_delete_own" on storage.objects;
create policy "vault_delete_own"
on storage.objects
for delete
to authenticated
using (
  bucket_id = 'vault'
  and (storage.foldername(name))[1] = (select auth.uid()::text)
);

-- ------------------------------------------------------------
-- FUNCTION: folder tree for one user
-- Useful for deleting a folder and its descendants.
-- ------------------------------------------------------------

create or replace function public.get_folder_tree(root_folder uuid)
returns table(id uuid)
language sql
security invoker
as $$
  with recursive tree as (
    select f.id
    from public.folders f
    where f.id = root_folder
      and f.user_id = auth.uid()

    union all

    select child.id
    from public.folders child
    join tree parent on child.parent_id = parent.id
    where child.user_id = auth.uid()
  )
  select id from tree;
$$;

grant execute on function public.get_folder_tree(uuid) to authenticated;
