-- ============================================================================
-- PHASE 13 — PRODUCTION FIXES (additive only; no DROP/TRUNCATE/DELETE)
-- Runs AFTER phase12_complete_platform_v5.sql and phase12_1_hardening.sql.
--
-- Fix 1: fn_is_admin_or_guard now includes the 'director' role.
--   The legacy helper (phase2_schema) only accepted ('admin','guard'), so a
--   user whose ONLY role in the school is 'director' was silently rejected by:
--     - fn_register_student's internal re-check
--       ("PERMISSION_DENIED: only guard/admin may register students")
--     - every RLS write policy that uses fn_is_admin_or_guard
--       (students, student_enrollments, classes, subjects, academic_years,
--        timetables, salaries, expenses, payments, transport...).
--   The function is SECURITY DEFINER + STABLE and keeps the same signature;
--   all existing policies pick up the fix automatically (no policy rewrites).
--
-- Fix 2: backfill missing staff records.
--   Accounts created by SuperAdmin via the create-platform-user Edge Function
--   got profiles + user_roles rows but NO row in guards/teachers/drivers/
--   parents, so they were invisible in the school console lists (which read
--   those tables under RLS). This backfill inserts the missing rows from
--   user_roles — INSERT-only, idempotent (ON CONFLICT DO NOTHING), never
--   touches existing rows or any data.
-- ============================================================================

-- ---- Fix 1 -----------------------------------------------------------------
create or replace function fn_is_admin_or_guard(p_school_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  -- 'director' is full school management staff: same write scope as admin.
  select fn_has_role(p_school_id, array['admin','guard','director']::app_role[]);
$$;

-- ---- Fix 2 -----------------------------------------------------------------
insert into guards (profile_id, school_id)
select ur.profile_id, ur.school_id
from user_roles ur
where ur.role = 'guard'::app_role
  and not exists (
    select 1 from guards g
    where g.profile_id = ur.profile_id and g.school_id = ur.school_id
  )
on conflict do nothing;

insert into teachers (profile_id, school_id)
select ur.profile_id, ur.school_id
from user_roles ur
where ur.role = 'teacher'::app_role
  and not exists (
    select 1 from teachers t
    where t.profile_id = ur.profile_id and t.school_id = ur.school_id
  )
on conflict do nothing;

insert into drivers (profile_id, school_id)
select ur.profile_id, ur.school_id
from user_roles ur
where ur.role = 'driver'::app_role
  and not exists (
    select 1 from drivers d
    where d.profile_id = ur.profile_id and d.school_id = ur.school_id
  )
on conflict do nothing;

insert into parents (profile_id, school_id)
select ur.profile_id, ur.school_id
from user_roles ur
where ur.role = 'parent'::app_role
  and not exists (
    select 1 from parents p
    where p.profile_id = ur.profile_id and p.school_id = ur.school_id
  )
on conflict do nothing;

-- ============================================================================
-- END OF PHASE 13 FIXES
-- ============================================================================
