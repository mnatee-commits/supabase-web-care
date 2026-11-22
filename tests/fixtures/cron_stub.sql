-- Local stand-in for pg_cron's two tables, with its row-level security.
-- For tests on a throwaway local Postgres only. Synthetic data only.
create schema cron;
create table cron.job (
  jobid bigint primary key, schedule text not null, command text not null,
  username text not null default current_user, active boolean not null default true, jobname text
);
create table cron.job_run_details (
  jobid bigint, runid bigserial primary key, username text default current_user,
  command text, status text, return_message text, start_time timestamptz, end_time timestamptz
);
alter table cron.job enable row level security;
alter table cron.job_run_details enable row level security;
create policy cron_job_policy on cron.job using (username = current_user);
create policy cron_job_run_details_policy on cron.job_run_details using (username = current_user);

insert into cron.job (jobid, schedule, command, jobname, active) values
  (1, '0 18 * * *', 'select 1 /* MARKER-COMMAND */', 'steady', true),
  (2, '*/5 * * * *', 'select 1', 'broken', true),
  (3, '0 3 * * *', 'select 1', 'recovered', true),
  (4, '0 0 1 * *', 'select 1', 'silent', true),
  (5, '0 0 * * *', 'select 1', 'switched_off', false),
  (6, '0 1 * * *', 'select 1', null, true);
insert into cron.job_run_details (jobid, status, return_message, start_time) values
  (1, 'succeeded', 'MARKER-MESSAGE', now() - interval '1 day'),
  (1, 'succeeded', null, now() - interval '2 days'),
  (2, 'succeeded', null, now() - interval '3 days'),
  (2, 'failed', 'ERROR: MARKER-MESSAGE', now() - interval '1 hour'),
  (2, 'running', null, now()),
  (3, 'failed', null, now() - interval '2 days'),
  (3, 'succeeded', null, now() - interval '1 day'),
  (4, 'succeeded', null, now() - interval '20 days'),
  (5, 'failed', null, now() - interval '1 day'),
  (6, 'succeeded', null, now() - interval '1 day');
