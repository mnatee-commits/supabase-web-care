-- Schema that follows the Supabase security checklist. The tests assert that
-- the checks stay quiet on it. Synthetic data only.

create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  total numeric(12, 2) not null default 0
);
create index orders_user_id_idx on public.orders (user_id);
alter table public.orders enable row level security;
alter table public.orders force row level security;

create policy orders_select_own on public.orders
  for select to authenticated
  using ((select auth.uid()) = user_id);
create policy orders_insert_own on public.orders
  for insert to authenticated
  with check ((select auth.uid()) = user_id);
create policy orders_update_own on public.orders
  for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);
create policy orders_delete_own on public.orders
  for delete to authenticated
  using ((select auth.uid()) = user_id);
grant select, insert, update, delete on public.orders to authenticated;

create view public.orders_view
  with (security_invoker = true, security_barrier = true) as
  select id, user_id, total from public.orders;
grant select on public.orders_view to authenticated;

-- Storage policies that cover every operation an upsert needs.
create policy "avatars select own" on storage.objects
  for select to authenticated
  using (bucket_id = 'avatars' and owner = (select auth.uid()));
create policy "avatars insert own" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'avatars' and owner = (select auth.uid()));
create policy "avatars update own" on storage.objects
  for update to authenticated
  using (bucket_id = 'avatars' and owner = (select auth.uid()))
  with check (bucket_id = 'avatars' and owner = (select auth.uid()));

insert into storage.buckets (id, name, public) values ('avatars', 'avatars', false);
insert into public.orders (user_id, total) values
  ('00000000-0000-4000-8000-000000000001', 10.00);
