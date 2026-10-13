-- Review before execution. Only public.user_notes is affected; records are preserved.
select grantee, privilege_type from information_schema.role_table_grants
where table_schema='public' and table_name='user_notes' order by grantee, privilege_type;
select role_name, privilege, has_table_privilege(role_name,'public.user_notes',privilege) as allowed
from (values ('anon'), ('authenticated')) roles(role_name)
cross join (values ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER')) actions(privilege);
begin;
alter table public.user_notes enable row level security;
revoke all on table public.user_notes from PUBLIC, anon, authenticated;
grant select, insert, update, delete on table public.user_notes to authenticated;
-- Restrictive policy also protects against a pre-existing permissive policy.
create policy stage4_owner_boundary on public.user_notes as restrictive for all to authenticated
using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);
create policy stage4_select on public.user_notes for select to authenticated
using ((select auth.uid()) = owner_id);
create policy stage4_insert on public.user_notes for insert to authenticated
with check ((select auth.uid()) = owner_id);
create policy stage4_update on public.user_notes for update to authenticated
using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);
create policy stage4_delete on public.user_notes for delete to authenticated
using ((select auth.uid()) = owner_id);
commit;
select grantee, privilege_type from information_schema.role_table_grants
where table_schema='public' and table_name='user_notes' order by grantee, privilege_type;
select role_name, privilege, has_table_privilege(role_name,'public.user_notes',privilege) as allowed
from (values ('anon'), ('authenticated')) roles(role_name)
cross join (values ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER')) actions(privilege);
