-- Kaupinkujan Bodarit: private, explicitly accepted sharing.
-- Run once in Supabase SQL Editor before merging the app PR.
create table if not exists public.training_shares (
 id uuid primary key default gen_random_uuid(),
 owner_id uuid not null references auth.users(id) on delete cascade,
 viewer_id uuid not null references auth.users(id) on delete cascade,
 status text not null default 'pending' check (status in ('pending','accepted')),
 created_at timestamptz not null default now(),
 unique(owner_id,viewer_id),
 check(owner_id <> viewer_id)
);
create table if not exists public.workout_reactions (
 id uuid primary key default gen_random_uuid(),
 session_id uuid not null references public.workout_sessions(id) on delete cascade,
 sender_id uuid not null references auth.users(id) on delete cascade,
 reaction text not null check (reaction in ('like','cheer')),
 created_at timestamptz not null default now(),
 unique(session_id,sender_id)
);
create index if not exists training_shares_viewer_idx on public.training_shares(viewer_id,status);
create index if not exists workout_reactions_session_idx on public.workout_reactions(session_id);
alter table public.training_shares enable row level security;
alter table public.workout_reactions enable row level security;
revoke all on public.training_shares from anon,authenticated;
revoke all on public.workout_reactions from anon,authenticated;

-- SECURITY DEFINER RPCs deliberately expose only explicitly authorized rows.
create or replace function public.bodarit_invite(p_email text)
returns text language plpgsql security definer set search_path = public, pg_temp as $$
declare v_target uuid; v_me uuid := auth.uid();
begin
 if v_me is null then raise exception 'Kirjaudu ensin'; end if;
 if length(trim(coalesce(p_email,''))) < 5 then raise exception 'Anna sähköpostiosoite'; end if;
 select id into v_target from auth.users where lower(email)=lower(trim(p_email)) limit 1;
 if v_target is null or v_target=v_me then return 'Kutsu ei onnistunut. Tarkista, että toinen käyttäjä on rekisteröitynyt eri tunnuksella.'; end if;
 insert into public.training_shares(owner_id,viewer_id,status) values(v_me,v_target,'pending')
 on conflict(owner_id,viewer_id) do nothing;
 return 'Kutsu lähetetty. Toinen käyttäjä hyväksyy sen omalla tunnuksellaan.';
end $$;

create or replace function public.bodarit_shares()
returns jsonb language sql security definer set search_path = public, pg_temp as $$
 select coalesce(jsonb_agg(jsonb_build_object(
 'id',s.id,'direction',case when s.owner_id=auth.uid() then 'out' else 'in' end,
 'status',s.status,
 'email',case when s.owner_id=auth.uid() then viewer.email else owner.email end,
 'owner_id',s.owner_id,'viewer_id',s.viewer_id
 ) order by s.created_at desc),'[]'::jsonb)
 from public.training_shares s
 join auth.users owner on owner.id=s.owner_id
 join auth.users viewer on viewer.id=s.viewer_id
 where auth.uid() is not null and (s.owner_id=auth.uid() or s.viewer_id=auth.uid());
$$;

create or replace function public.bodarit_respond(p_share uuid,p_accept boolean)
returns void language plpgsql security definer set search_path = public, pg_temp as $$
begin
 if p_accept then
  update public.training_shares set status='accepted'
  where id=p_share and viewer_id=auth.uid() and status='pending';
 else
  delete from public.training_shares where id=p_share and (viewer_id=auth.uid() or owner_id=auth.uid());
 end if;
 if not found then raise exception 'Kutsua ei löytynyt tai käyttöoikeus puuttuu'; end if;
end $$;

-- Return only workouts owned by the accepted share owner. Never allow edits through this function.
create or replace function public.bodarit_shared_workouts(p_owner uuid)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare result jsonb;
begin
 if auth.uid() is null or not exists (
  select 1 from public.training_shares where owner_id=p_owner and viewer_id=auth.uid() and status='accepted'
 ) then raise exception 'Katseluoikeutta ei ole hyväksytty'; end if;
 select coalesce(jsonb_agg(item order by performed_at desc),'[]'::jsonb) into result
 from (
  select s.performed_at, jsonb_build_object(
   'id',s.id,'date',s.performed_at,'notes',s.notes,
   'profile',p.name,'workout',w.name,'description',w.description,
   'exercises',coalesce((
    select jsonb_agg(jsonb_build_object(
     'name',es.exercise_name,'notes',es.notes,
     'sets',coalesce((select jsonb_agg(jsonb_build_object('kg',st.weight,'reps',st.reps) order by st.set_number)
       from public.exercise_sets st where st.exercise_session_id=es.id),'[]'::jsonb)
    ) order by es.position)
    from public.exercise_sessions es where es.session_id=s.id
   ),'[]'::jsonb),
   'reactions',coalesce((
    select jsonb_agg(jsonb_build_object('sender_id',r.sender_id,'reaction',r.reaction))
    from public.workout_reactions r where r.session_id=s.id
   ),'[]'::jsonb)
  ) item
  from public.workout_sessions s
  join public.training_profiles p on p.id=s.profile_id
  join public.workouts w on w.id=s.workout_id
  where p.owner_id=p_owner
 ) x;
 return coalesce(result,'[]'::jsonb);
end $$;

create or replace function public.bodarit_react(p_session uuid,p_reaction text)
returns void language plpgsql security definer set search_path = public, pg_temp as $$
begin
 if p_reaction not in ('like','cheer') then raise exception 'Tuntematon reaktio'; end if;
 if not exists (
  select 1 from public.workout_sessions s
  join public.training_profiles p on p.id=s.profile_id
  join public.training_shares sh on sh.owner_id=p.owner_id
  where s.id=p_session and sh.viewer_id=auth.uid() and sh.status='accepted'
 ) then raise exception 'Ei oikeutta kannustaa tätä treeniä'; end if;
 insert into public.workout_reactions(session_id,sender_id,reaction)
 values(p_session,auth.uid(),p_reaction)
 on conflict(session_id,sender_id) do update set reaction=excluded.reaction;
end $$;
revoke all on function public.bodarit_invite(text) from public;
revoke all on function public.bodarit_shares() from public;
revoke all on function public.bodarit_respond(uuid,boolean) from public;
revoke all on function public.bodarit_shared_workouts(uuid) from public;
revoke all on function public.bodarit_react(uuid,text) from public;
grant execute on function public.bodarit_invite(text),public.bodarit_shares(),public.bodarit_respond(uuid,boolean),public.bodarit_shared_workouts(uuid),public.bodarit_react(uuid,text) to authenticated;
