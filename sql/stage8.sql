begin;
create table if not exists public.vault_notices (
  id uuid primary key, title text not null, body text not null
);
alter table public.vault_notices enable row level security;
revoke all on public.vault_notices from public, anon, authenticated;
grant select, update on public.vault_notices to service_role;
insert into public.vault_notices (id, title, body)
values ('00000000-0000-4000-8000-000000000008', '학습용 가상 공지', '가상 공지입니다. 실제 학생 자료는 넣지 않습니다.')
on conflict (id) do nothing;
commit;
