-- 10단계: 비공개 가상 메모 사본과 한 건 복원 함수. 학습용 Supabase SQL Editor에서 한 번 실행합니다.
-- 기존 notes 자료와 트리거는 지우지 않고, 사본 표는 서버 전용 키(service_role)만 읽을 수 있습니다.
begin;
create table if not exists public.note_backups (
  id uuid primary key, owner_id uuid not null, title text not null, body text not null,
  created_at timestamptz not null, content_hash text not null
);
create table if not exists public.restore_audit (
  sequence bigint generated always as identity primary key, note_id uuid not null,
  action text not null, at timestamptz not null default now()
);
alter table public.note_backups enable row level security;
alter table public.restore_audit enable row level security;
revoke all on public.note_backups, public.restore_audit from public, anon, authenticated;
revoke all on public.note_backups, public.restore_audit from service_role;
grant select on public.note_backups, public.restore_audit to service_role;

-- ID·소유자·제목·본문을 묶은 내용 해시
create or replace function public.note_content_hash(note_id uuid, note_owner uuid, note_title text, note_body text)
returns text language sql immutable strict set search_path = pg_catalog as $$
  select encode(sha256(convert_to(jsonb_build_object('id', note_id, 'owner_id', note_owner, 'title', note_title, 'body', note_body)::text, 'UTF8')), 'hex')
$$;

-- 새 메모가 생길 때마다 사본을 한 번만 저장합니다(이미 있으면 덮어쓰지 않음).
create or replace function public.capture_note_backup()
returns trigger language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  insert into public.note_backups (id, owner_id, title, body, created_at, content_hash)
  values (new.id, new.owner_id, new.title, new.body, new.created_at, public.note_content_hash(new.id, new.owner_id, new.title, new.body))
  on conflict (id) do nothing;
  return new;
end $$;
revoke all on function public.capture_note_backup() from public, anon, authenticated, service_role;
do $$ begin
  if not exists (select 1 from pg_trigger where tgname = 'capture_note_backup_insert' and tgrelid = 'public.notes'::regclass) then
    create trigger capture_note_backup_insert after insert on public.notes for each row execute function public.capture_note_backup();
  end if;
end $$;
-- 지금 있는 가상 메모의 사본(침해 전 상태). 이미 있는 사본은 그대로 둡니다.
insert into public.note_backups (id, owner_id, title, body, created_at, content_hash)
select id, owner_id, title, body, created_at, public.note_content_hash(id, owner_id, title, body) from public.notes
on conflict (id) do nothing;

-- 검증된 소유자의 사본 한 건만 복원합니다. 사본 해시를 다시 계산해 대조하고, 다른 메모는 건드리지 않습니다.
create or replace function public.restore_note(target_note_id uuid, verified_owner_id uuid)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public as $$
declare saved public.note_backups%rowtype; current_owner uuid; restored public.notes%rowtype;
begin
  perform pg_advisory_xact_lock(hashtextextended('note:' || target_note_id::text, 0));
  select * into saved from public.note_backups where id = target_note_id and owner_id = verified_owner_id for update;
  if not found then raise exception using errcode = 'P0002', message = 'backup_not_found'; end if;
  if saved.content_hash <> public.note_content_hash(saved.id, saved.owner_id, saved.title, saved.body) then
    raise exception using errcode = 'P0001', message = 'backup_integrity_failed';
  end if;
  select owner_id into current_owner from public.notes where id = target_note_id for update;
  if found and current_owner <> saved.owner_id then raise exception using errcode = 'P0001', message = 'owner_mismatch'; end if;
  insert into public.notes (id, owner_id, title, body, created_at)
  values (saved.id, saved.owner_id, saved.title, saved.body, saved.created_at)
  on conflict (id) do update set title = excluded.title, body = excluded.body, created_at = excluded.created_at
  where public.notes.owner_id = saved.owner_id;
  select * into restored from public.notes where id = saved.id;
  if restored.owner_id <> saved.owner_id or public.note_content_hash(restored.id, restored.owner_id, restored.title, restored.body) <> saved.content_hash then
    raise exception using errcode = 'P0001', message = 'restore_integrity_failed';
  end if;
  insert into public.restore_audit (note_id, action) values (saved.id, 'verified_single_note_restore');
  return jsonb_build_object('id', saved.id, 'verified', true, 'content_hash', saved.content_hash);
end $$;
revoke all on function public.restore_note(uuid, uuid) from public, anon, authenticated;
grant execute on function public.restore_note(uuid, uuid) to service_role;
commit;
