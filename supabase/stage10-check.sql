-- 가상 ID만 쓰고 모든 변경을 되돌립니다(rollback). 실제 학생 자료는 쓰지 않습니다.
begin;
do $$
declare fixture_id uuid := gen_random_uuid(); fixture_owner uuid := gen_random_uuid();
  outsider uuid := gen_random_uuid(); original_hash text; outcome jsonb; denied boolean := false;
begin
  insert into public.notes (id, owner_id, title, body) values (fixture_id, fixture_owner, 'Fictional B fixture', 'No real student information');
  select content_hash into original_hash from public.note_backups where id = fixture_id;
  if original_hash is null then raise exception 'backup_capture_failed'; end if;
  update public.notes set body = 'Fictional tamper' where id = fixture_id;
  outcome := public.restore_note(fixture_id, fixture_owner);
  if outcome->>'content_hash' <> original_hash or outcome->>'verified' <> 'true' then raise exception 'tamper_restore_failed'; end if;
  delete from public.notes where id = fixture_id;
  outcome := public.restore_note(fixture_id, fixture_owner);
  if outcome->>'content_hash' <> original_hash then raise exception 'deleted_restore_failed'; end if;
  begin perform public.restore_note(fixture_id, outsider); exception when sqlstate 'P0002' then denied := true; end;
  if not denied then raise exception 'cross_owner_restore_allowed'; end if;
end $$;
rollback;
select 'passed: tamper/delete restore, owner/hash check; fictional transaction rolled back' as verification;
