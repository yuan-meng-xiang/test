create or replace function private.survey_rate_limited(
  scope_name text,
  client_key text,
  max_events integer,
  window_seconds integer
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_events integer;
begin
  delete from private.survey_rate_limit_events
  where created_at < now() - interval '1 hour';

  select count(*) into current_events
  from private.survey_rate_limit_events events
  where events.scope = scope_name
    and events.client_key = survey_rate_limited.client_key
    and events.created_at >= now() - make_interval(secs => window_seconds);

  if current_events >= max_events then
    return true;
  end if;

  insert into private.survey_rate_limit_events (scope, client_key)
  values (scope_name, survey_rate_limited.client_key);

  return false;
end;
$$;

grant execute on function private.survey_rate_limited(text, text, integer, integer) to anon, authenticated;
