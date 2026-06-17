create or replace function private.survey_admin_clear(token text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not private.survey_admin_authorized(token) then
    return jsonb_build_object('ok', false, 'error', 'unauthorized');
  end if;
  delete from public.survey_responses where true;
  return jsonb_build_object('ok', true, 'count', 0);
end;
$$;

grant execute on function private.survey_admin_clear(text) to anon, authenticated;
