-- حبر: قاعدة البيانات — انسخ الملف كامل والصقه في SQL Editor (Database مو Logs) واضغط Run. تقدر تشغّله أكثر من مرة.
-- الرسائل تنحفظ مشفّرة من الهاتف نفسه (ما نقدر نقرأها هنا)، وتنحذف نهائيًا لما يخلص مؤقتها.
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.hb_users (
  id          uuid primary key default gen_random_uuid(),
  created_at  timestamptz not null default now(),
  username    text unique check (username ~ '^[a-z0-9_.]{3,20}$'),
  phone       text unique check (phone ~ '^[0-9]{10,15}$'),
  email       text unique check (char_length(email) <= 100 and email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  phone_ok    boolean not null default false,
  email_ok    boolean not null default false,
  name        text check (char_length(name) <= 40),
  pubkey      text not null check (char_length(pubkey) between 40 and 400),
  secret_hash text not null,
  last_seen   timestamptz not null default now(),
  show_online boolean not null default true,
  show_seen   boolean not null default true,
  receipts    boolean not null default true,
  status      text not null default 'ok' check (status in ('ok','blocked')),
  constraint hb_users_one_id check (username is not null or phone is not null or email is not null)
);

create table if not exists public.hb_msgs (
  id          uuid primary key default gen_random_uuid(),
  created_at  timestamptz not null default now(),
  from_id     uuid not null references public.hb_users(id) on delete cascade,
  to_id       uuid not null references public.hb_users(id) on delete cascade,
  kind        text not null check (kind in ('text','photo','video','file','sys')),
  body        text not null check (char_length(body) <= 20000),   -- مشفّر
  media       text check (media ~ '^m/[0-9a-z-]{20,60}$'),
  timer       int not null default 0 check (timer in (0,5,30,60,300,3600,604800)),  -- 0 = بعد القراءة
  read_at     timestamptz,
  expires_at  timestamptz
);
create index if not exists hb_msgs_to on public.hb_msgs(to_id);
create index if not exists hb_msgs_from on public.hb_msgs(from_id);

create table if not exists public.hb_blocks (
  user_id    uuid not null references public.hb_users(id) on delete cascade,
  blocked_id uuid not null references public.hb_users(id) on delete cascade,
  primary key (user_id, blocked_id)
);

create table if not exists public.hb_reports (
  id          bigserial primary key,
  created_at  timestamptz not null default now(),
  reporter    uuid references public.hb_users(id) on delete set null,
  target      uuid references public.hb_users(id) on delete cascade,
  reason      text not null default '',
  evidence    text not null default ''      -- نص يرسله المبلّغ بنفسه من محادثته
);

alter table public.hb_users enable row level security;
alter table public.hb_msgs enable row level security;
alter table public.hb_blocks enable row level security;
alter table public.hb_reports enable row level security;
revoke all on public.hb_users, public.hb_msgs, public.hb_blocks, public.hb_reports from anon, authenticated;

-- تخزين المرفقات (مشفّرة قبل الرفع، وأسماؤها عشوائية)
insert into storage.buckets (id, name, public, file_size_limit)
values ('hibr', 'hibr', true, 26214400)
on conflict (id) do update set public = true, file_size_limit = 26214400;
drop policy if exists "hibr upload" on storage.objects;
create policy "hibr upload" on storage.objects for insert to anon, authenticated
  with check (bucket_id = 'hibr' and name ~ '^m/[0-9a-z-]{20,60}$');
drop policy if exists "hibr delete" on storage.objects;
create policy "hibr delete" on storage.objects for delete to anon, authenticated
  using (bucket_id = 'hibr' and name ~ '^m/[0-9a-z-]{20,60}$');

-- helpers -----------------------------------------------------------------
create or replace function public._hb_me(p_id uuid, p_secret text) returns public.hb_users
language plpgsql security definer set search_path = public, extensions as $$
declare u hb_users;
begin
  select * into u from hb_users where id = p_id;
  if u.id is null or u.secret_hash <> crypt(p_secret, u.secret_hash) then raise exception 'الحساب مو موجود على هالهاتف'; end if;
  if u.status = 'blocked' then raise exception 'حسابك موقوف بسبب بلاغات'; end if;
  update hb_users set last_seen = now() where id = u.id;
  return u;
end $$;

create or replace function public._hb_card(u public.hb_users, viewer uuid) returns json
language sql stable as $$
  select json_build_object('id', u.id, 'username', u.username, 'name', u.name, 'pubkey', u.pubkey,
    'online', u.show_online and u.last_seen > now() - interval '20 seconds',
    'last_seen', case when u.show_seen then u.last_seen end)
$$;

-- account -----------------------------------------------------------------
drop function if exists public.hb_register(text, text, text, text, text);
create function public.hb_register(p_username text, p_phone text, p_email text, p_name text, p_pubkey text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare v_secret text := encode(gen_random_bytes(24), 'hex'); v_id uuid;
  v_user text := nullif(lower(trim(coalesce(p_username, ''))), '');
  v_phone text := nullif(regexp_replace(coalesce(p_phone, ''), '\D', '', 'g'), '');
  v_mail text := nullif(lower(trim(coalesce(p_email, ''))), '');
begin
  if length(v_phone) = 8 then v_phone := '968' || v_phone; end if;
  if v_user is null and v_phone is null and v_mail is null then raise exception 'اكتب واحد على الأقل: اسم المستخدم أو الهاتف أو الإيميل'; end if;
  if v_user is not null and exists (select 1 from hb_users where username = v_user) then raise exception 'اسم المستخدم مأخوذ، جرّب غيره'; end if;
  if v_phone is not null and exists (select 1 from hb_users where phone = v_phone) then raise exception 'هذا الرقم مسجّل في حبر من قبل'; end if;
  if v_mail is not null and exists (select 1 from hb_users where email = v_mail) then raise exception 'هذا الإيميل مسجّل في حبر من قبل'; end if;
  if (select count(*) from hb_users where created_at > now() - interval '1 hour') > 100 then raise exception 'ضغط تسجيلات كثير، حاول بعد شوي'; end if;
  insert into hb_users(username, phone, email, name, pubkey, secret_hash)
  values (v_user, v_phone, v_mail, nullif(trim(coalesce(p_name, '')), ''), p_pubkey, crypt(v_secret, gen_salt('bf')))
  returning id into v_id;
  return json_build_object('id', v_id, 'secret', v_secret);
end $$;

create or replace function public.hb_me(p_id uuid, p_secret text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare u hb_users := _hb_me(p_id, p_secret);
begin
  return json_build_object('id', u.id, 'username', u.username, 'phone', u.phone, 'email', u.email, 'phone_ok', u.phone_ok, 'email_ok', u.email_ok,
    'name', u.name, 'show_online', u.show_online, 'show_seen', u.show_seen, 'receipts', u.receipts);
end $$;

create or replace function public.hb_settings(p_id uuid, p_secret text, p_online boolean, p_seen boolean, p_receipts boolean)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare u hb_users := _hb_me(p_id, p_secret);
begin
  update hb_users set show_online = p_online, show_seen = p_seen, receipts = p_receipts where id = u.id;
end $$;

create or replace function public.hb_delete_account(p_id uuid, p_secret text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare u hb_users := _hb_me(p_id, p_secret); v_media text[];
begin
  select coalesce(array_agg(media), '{}') into v_media from hb_msgs where (from_id = u.id or to_id = u.id) and media is not null;
  delete from hb_users where id = u.id;
  return json_build_object('media', v_media);
end $$;

-- people ------------------------------------------------------------------
create or replace function public.hb_find(p_id uuid, p_secret text, p_q text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare me hb_users := _hb_me(p_id, p_secret); q text := lower(trim(coalesce(p_q, ''))); d text := regexp_replace(q, '\D', '', 'g'); r hb_users;
begin
  q := regexp_replace(q, '^@', '');
  select * into r from hb_users x where x.status = 'ok' and x.id <> me.id and (
      x.username = q
      or (x.email_ok and x.email = q)
      or (x.phone_ok and length(d) >= 8 and (x.phone = d or x.phone = '968' || d)))
    limit 1;
  if r.id is null then return null; end if;
  return _hb_card(r, me.id);
end $$;

create or replace function public.hb_peers(p_id uuid, p_secret text, p_ids uuid[])
returns json language plpgsql security definer set search_path = public, extensions as $$
declare me hb_users := _hb_me(p_id, p_secret);
begin
  return coalesce((select json_agg(_hb_card(x, me.id)) from hb_users x where x.id = any(p_ids) and x.status = 'ok'), '[]'::json);
end $$;

create or replace function public.hb_block(p_id uuid, p_secret text, p_target uuid, p_on boolean)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare me hb_users := _hb_me(p_id, p_secret);
begin
  if p_on then insert into hb_blocks values (me.id, p_target) on conflict do nothing;
  else delete from hb_blocks where user_id = me.id and blocked_id = p_target; end if;
end $$;

create or replace function public.hb_report(p_id uuid, p_secret text, p_target uuid, p_reason text, p_evidence text)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare me hb_users := _hb_me(p_id, p_secret);
begin
  if (select count(*) from hb_reports where reporter = me.id and created_at > now() - interval '1 day') >= 20 then raise exception 'بلاغات كثيرة اليوم'; end if;
  insert into hb_reports(reporter, target, reason, evidence) values (me.id, p_target, left(coalesce(p_reason, ''), 200), left(coalesce(p_evidence, ''), 4000));
end $$;

-- messages ----------------------------------------------------------------
create or replace function public.hb_send(p_id uuid, p_secret text, p_to uuid, p_kind text, p_body text, p_timer int, p_media text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare me hb_users := _hb_me(p_id, p_secret); v_id uuid; v_at timestamptz;
begin
  if not exists (select 1 from hb_users where id = p_to and status = 'ok') then raise exception 'الشخص مو موجود'; end if;
  if (select count(*) from hb_msgs where from_id = me.id and created_at > now() - interval '1 minute') >= 60 then raise exception 'رسائل كثيرة، هدّي شوي'; end if;
  -- المحظور ما توصل رسائله، بس يحسب إنها انرسلت
  if exists (select 1 from hb_blocks where user_id = p_to and blocked_id = me.id) then
    return json_build_object('id', gen_random_uuid(), 'created_at', now());
  end if;
  insert into hb_msgs(from_id, to_id, kind, body, timer, media) values (me.id, p_to, p_kind, p_body, coalesce(p_timer, 0), p_media)
  returning id, created_at into v_id, v_at;
  return json_build_object('id', v_id, 'created_at', v_at);
end $$;

-- كل الرسائل الحية (لي ومني)، ويحذف المنتهية نهائيًا
create or replace function public.hb_inbox(p_id uuid, p_secret text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare me hb_users := _hb_me(p_id, p_secret); v_gone json;
begin
  with g as (
    delete from hb_msgs where (from_id = me.id or to_id = me.id)
      and (expires_at < now() or (read_at is null and created_at < now() - interval '14 days'))
    returning media)
  select coalesce(json_agg(media) filter (where media is not null), '[]'::json) into v_gone from g;
  return json_build_object('now', now(), 'gone_media', v_gone, 'msgs', coalesce((
    select json_agg(json_build_object('id', m.id, 'created_at', m.created_at, 'from', m.from_id, 'to', m.to_id, 'kind', m.kind, 'body', m.body,
      'media', m.media, 'timer', m.timer,
      'expires_at', case when m.to_id = me.id or r.receipts then m.expires_at end,
      'read_at', case when m.to_id = me.id or r.receipts then m.read_at end) order by m.created_at)
    from hb_msgs m join hb_users r on r.id = m.to_id
    where (m.from_id = me.id or m.to_id = me.id) and (m.expires_at is null or m.expires_at >= now())), '[]'::json));
end $$;

-- قرأت: يبدأ المؤقت (المؤقتات بالثواني). «بعد القراءة» ينتهي بـ hb_done
create or replace function public.hb_read(p_id uuid, p_secret text, p_ids uuid[])
returns void language plpgsql security definer set search_path = public, extensions as $$
declare me hb_users := _hb_me(p_id, p_secret);
begin
  update hb_msgs set read_at = now(), expires_at = case when timer > 0 then now() + make_interval(secs => timer) end
  where to_id = me.id and id = any(p_ids) and read_at is null;
end $$;

create or replace function public.hb_done(p_id uuid, p_secret text, p_ids uuid[])
returns void language plpgsql security definer set search_path = public, extensions as $$
declare me hb_users := _hb_me(p_id, p_secret);
begin
  update hb_msgs set expires_at = now() where to_id = me.id and id = any(p_ids) and read_at is not null and timer = 0;
end $$;

create or replace function public.hb_clear(p_id uuid, p_secret text, p_peer uuid)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare me hb_users := _hb_me(p_id, p_secret); v_media json;
begin
  with g as (delete from hb_msgs where (from_id = me.id and to_id = p_peer) or (from_id = p_peer and to_id = me.id) returning media)
  select coalesce(json_agg(media) filter (where media is not null), '[]'::json) into v_media from g;
  return v_media;
end $$;

-- admin (نفس رمز المدير) ---------------------------------------------------
create or replace function public.hb_admin_reports(p_pass text)
returns json language plpgsql security definer set search_path = public as $$
begin
  perform _check_admin(p_pass);
  return coalesce((select json_agg(json_build_object('id', r.id, 'created_at', r.created_at, 'reason', r.reason, 'evidence', r.evidence,
      'target', r.target, 'target_name', coalesce('@' || t.username, t.name, '؟'), 'target_status', t.status,
      'target_reports', (select count(*) from hb_reports x where x.target = r.target),
      'reporter_name', coalesce('@' || f.username, f.name, '؟')) order by r.created_at desc)
    from hb_reports r left join hb_users t on t.id = r.target left join hb_users f on f.id = r.reporter), '[]'::json);
end $$;

create or replace function public.hb_admin_set(p_pass text, p_user uuid, p_status text)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform _check_admin(p_pass);
  if p_status not in ('ok','blocked') then raise exception 'حالة غير صحيحة'; end if;
  update hb_users set status = p_status where id = p_user;
end $$;

create or replace function public.hb_admin_dismiss(p_pass text, p_report bigint)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform _check_admin(p_pass);
  delete from hb_reports where id = p_report;
end $$;

create or replace function public.hb_admin_stats(p_pass text)
returns json language plpgsql security definer set search_path = public as $$
begin
  perform _check_admin(p_pass);
  return json_build_object('users', (select count(*) from hb_users), 'active_today', (select count(*) from hb_users where last_seen > now() - interval '1 day'),
    'live_msgs', (select count(*) from hb_msgs), 'reports', (select count(*) from hb_reports));
end $$;

revoke all on function public._hb_me(uuid, text), public._hb_card(public.hb_users, uuid) from public, anon, authenticated;
grant execute on function
  public.hb_register(text, text, text, text, text), public.hb_me(uuid, text), public.hb_settings(uuid, text, boolean, boolean, boolean),
  public.hb_delete_account(uuid, text), public.hb_find(uuid, text, text), public.hb_peers(uuid, text, uuid[]),
  public.hb_block(uuid, text, uuid, boolean), public.hb_report(uuid, text, uuid, text, text),
  public.hb_send(uuid, text, uuid, text, text, int, text), public.hb_inbox(uuid, text), public.hb_read(uuid, text, uuid[]),
  public.hb_done(uuid, text, uuid[]), public.hb_clear(uuid, text, uuid),
  public.hb_admin_reports(text), public.hb_admin_set(text, uuid, text), public.hb_admin_dismiss(text, bigint), public.hb_admin_stats(text)
to anon, authenticated;
