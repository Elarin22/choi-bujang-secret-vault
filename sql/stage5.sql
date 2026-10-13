-- Review before execution. Only the learning memo table is changed; rows are preserved.
select grantee, privilege_type from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'user_notes' order by grantee, privilege_type;
select role_name, privilege, has_table_privilege(role_name, 'public.user_notes', privilege) as allowed
from (values ('anon'), ('authenticated')) roles(role_name)
cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) actions(privilege);

begin;
alter table public.user_notes enable row level security;
revoke all on table public.user_notes from PUBLIC, anon, authenticated;
grant select, insert, update, delete on table public.user_notes to service_role;
commit;

select grantee, privilege_type from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'user_notes' order by grantee, privilege_type;
select role_name, privilege, has_table_privilege(role_name, 'public.user_notes', privilege) as allowed
from (values ('anon'), ('authenticated')) roles(role_name)
cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) actions(privilege);
