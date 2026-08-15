-- 001_pending_actions.sql
-- Run once in the Supabase SQL editor.
-- Queue of Discord-side report actions for the bot to pick up.

create table if not exists public.pending_actions (
    id            bigint generated always as identity primary key,
    report_id     text        not null references public.reports (report_id) on delete cascade,
    action        text        not null,   -- validate | invalidate | investigate | contact_reporter
    requested_by  text        not null,
    status        text        not null default 'pending',  -- pending | success | failed
    result_note   text,
    created_at    timestamptz not null,
    completed_at  timestamptz
);

create index if not exists idx_pending_actions_status
    on public.pending_actions (status, created_at);
