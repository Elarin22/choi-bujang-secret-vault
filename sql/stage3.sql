begin;
create table if not exists public.user_notes (
  id uuid primary key,
  owner_id uuid not null,
  title text not null check (char_length(title) between 1 and 200),
  body text not null check (char_length(body) <= 10000),
  created_at timestamptz not null default now()
);
alter table public.user_notes enable row level security;
revoke all on table public.user_notes from anon, authenticated;
grant select, insert, update, delete on table public.user_notes to service_role;
commit;
-- public.notes and its four fictional records are preserved.
