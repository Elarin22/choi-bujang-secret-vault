-- Only newly generated fictional fixture IDs; all mutations are rolled back.
begin;
do $$
declare fixture_id uuid := gen_random_uuid(); fixture_owner uuid := gen_random_uuid();
  outsider uuid := gen_random_uuid(); original_hash text; outcome jsonb; denied boolean := false;
begin
  insert into public.user_notes (id, owner_id, title, body) values (fixture_id, fixture_owner, 'Fictional B fixture', 'No real student information');
  select content_hash into original_hash from public.vault_note_backups where id = fixture_id;
  if original_hash is null then raise exception 'backup_capture_failed'; end if;
  update public.user_notes set body = 'Fictional tamper' where id = fixture_id;
  outcome := public.vault_restore_note(fixture_id, fixture_owner);
  if outcome->>'content_hash' <> original_hash or outcome->>'verified' <> 'true' then raise exception 'tamper_restore_failed'; end if;
  delete from public.user_notes where id = fixture_id;
  outcome := public.vault_restore_note(fixture_id, fixture_owner);
  if outcome->>'content_hash' <> original_hash then raise exception 'deleted_restore_failed'; end if;
  begin perform public.vault_restore_note(fixture_id, outsider); exception when sqlstate 'P0002' then denied := true; end;
  if not denied then raise exception 'cross_owner_restore_allowed'; end if;
end $$;
rollback;
select 'passed: tamper/delete restore, owner/hash check; fictional transaction rolled back' as verification;
