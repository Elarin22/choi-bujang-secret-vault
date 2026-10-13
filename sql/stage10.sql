begin;
create table if not exists public.vault_note_backups (
  id uuid primary key, owner_id uuid not null, title text not null, body text not null,
  created_at timestamptz not null, content_hash text not null
);
create table if not exists public.vault_restore_audit (
  sequence bigint generated always as identity primary key, note_id uuid not null,
  action text not null, at timestamptz not null default now()
);
alter table public.vault_note_backups enable row level security;
alter table public.vault_restore_audit enable row level security;
revoke all on public.vault_note_backups, public.vault_restore_audit from public, anon, authenticated;
revoke all on public.vault_note_backups, public.vault_restore_audit from service_role;
grant select on public.vault_note_backups, public.vault_restore_audit to service_role;

create or replace function public.vault_note_hash(note_id uuid, note_owner uuid, note_title text, note_body text)
returns text language sql immutable strict set search_path = pg_catalog as $$
  select encode(sha256(convert_to(jsonb_build_object('id', note_id, 'owner_id', note_owner, 'title', note_title, 'body', note_body)::text, 'UTF8')), 'hex')
$$;

create or replace function public.vault_capture_note()
returns trigger language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  insert into public.vault_note_backups (id, owner_id, title, body, created_at, content_hash)
  values (new.id, new.owner_id, new.title, new.body, new.created_at, public.vault_note_hash(new.id, new.owner_id, new.title, new.body))
  on conflict (id) do nothing;
  return new;
end $$;
revoke all on function public.vault_capture_note() from public, anon, authenticated, service_role;
-- Preserve any existing trigger and user data; install once and leave backups immutable.
do $$ begin
  if not exists (select 1 from pg_trigger where tgname = 'vault_capture_note_insert' and tgrelid = 'public.user_notes'::regclass) then
    create trigger vault_capture_note_insert after insert on public.user_notes for each row execute function public.vault_capture_note();
  end if;
end $$;
insert into public.vault_note_backups (id, owner_id, title, body, created_at, content_hash)
select id, owner_id, title, body, created_at, public.vault_note_hash(id, owner_id, title, body) from public.user_notes
on conflict (id) do nothing;

create or replace function public.vault_restore_note(target_note_id uuid, verified_owner_id uuid)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public as $$
declare saved public.vault_note_backups%rowtype; current_owner uuid; restored public.user_notes%rowtype;
begin
  perform pg_advisory_xact_lock(hashtextextended('vault-note:' || target_note_id::text, 0));
  select * into saved from public.vault_note_backups where id = target_note_id and owner_id = verified_owner_id for update;
  if not found then raise exception using errcode = 'P0002', message = 'backup_not_found'; end if;
  if saved.content_hash <> public.vault_note_hash(saved.id, saved.owner_id, saved.title, saved.body) then
    raise exception using errcode = 'P0001', message = 'backup_integrity_failed';
  end if;
  select owner_id into current_owner from public.user_notes where id = target_note_id for update;
  if found and current_owner <> saved.owner_id then raise exception using errcode = 'P0001', message = 'owner_mismatch'; end if;
  insert into public.user_notes (id, owner_id, title, body, created_at)
  values (saved.id, saved.owner_id, saved.title, saved.body, saved.created_at)
  on conflict (id) do update set title = excluded.title, body = excluded.body, created_at = excluded.created_at
  where public.user_notes.owner_id = saved.owner_id;
  select * into restored from public.user_notes where id = saved.id;
  if restored.owner_id <> saved.owner_id or public.vault_note_hash(restored.id, restored.owner_id, restored.title, restored.body) <> saved.content_hash then
    raise exception using errcode = 'P0001', message = 'restore_integrity_failed';
  end if;
  insert into public.vault_restore_audit (note_id, action) values (saved.id, 'verified_single_note_restore');
  return jsonb_build_object('id', saved.id, 'verified', true, 'content_hash', saved.content_hash);
end $$;
revoke all on function public.vault_restore_note(uuid, uuid) from public, anon, authenticated;
grant execute on function public.vault_restore_note(uuid, uuid) to service_role;
commit;
