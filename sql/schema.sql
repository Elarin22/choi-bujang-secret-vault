begin;
create table if not exists public.notes (
  id integer primary key,
  owner_id uuid,
  title text not null,
  content text not null
);
alter table public.notes enable row level security;
revoke all on table public.notes from anon, authenticated;
grant select on table public.notes to service_role;
commit;
