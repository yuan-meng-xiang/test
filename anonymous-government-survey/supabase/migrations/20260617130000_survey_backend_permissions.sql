alter table private.survey_admin_credentials enable row level security;
alter table private.survey_admin_sessions enable row level security;
alter table private.survey_rate_limit_events enable row level security;

create or replace function private.survey_admin_export(token text)
returns jsonb
language sql
security definer
set search_path = ''
as $$
  select case
    when not private.survey_admin_authorized(token) then
      jsonb_build_object('ok', false, 'error', 'unauthorized')
    else
      jsonb_build_object(
        'ok', true,
        'rows', coalesce((
          select jsonb_agg(to_jsonb(rows) - 'submitted_sort' order by rows.submitted_sort)
          from (
            select
              submitted_at as submitted_sort,
              to_char(submitted_at at time zone 'Asia/Shanghai', 'YYYY-MM-DD HH24:MI:SS') || ' +0800' as submitted_at,
              q1 as "Q1", q2 as "Q2", q3 as "Q3", q4 as "Q4", q5 as "Q5", q6 as "Q6", q7 as "Q7", q8 as "Q8",
              q9 as "Q9", q10 as "Q10", q11 as "Q11", q12 as "Q12", q13 as "Q13", q14 as "Q14", q15 as "Q15",
              q16 as "Q16", q17 as "Q17", q18 as "Q18", q19 as "Q19", q20 as "Q20", q21 as "Q21", q22 as "Q22",
              q23 as "Q23", q24 as "Q24", q25 as "Q25", q26 as "Q26", q27 as "Q27", q28 as "Q28", q29 as "Q29",
              q30 as "Q30", q31 as "Q31"
            from public.survey_responses
            order by submitted_at
          ) rows
        ), '[]'::jsonb)
      )
  end;
$$;

grant usage on schema private to anon, authenticated;
grant execute on all functions in schema private to anon, authenticated;
