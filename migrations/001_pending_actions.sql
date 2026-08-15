-- 001_pending_actions.sql
-- Run once in the Supabase SQL editor.
-- Queue of Discord-side report actions for the bot to pick up.

-- Ensure reports.report_id has an explicit unique constraint (some Supabase
-- versions only create a unique index from the column-level UNIQUE keyword,
-- which foreign keys don't accept as a matching key).
DO $$ BEGIN
    ALTER TABLE reports ADD CONSTRAINT reports_report_id_key UNIQUE (report_id);
EXCEPTION
    WHEN duplicate_object THEN NULL;  -- constraint already exists, skip
END $$;

create table if not exists public.pending_actions (
    id            bigint generated always as identity primary key,
    report_id     text        not null references public.reports (report_id) on delete cascade,
    action        text        not null,   -- validate | invalidate | investigate | contact_reporter
    requested_by  text        not null,
    reason        text,                  -- optional reason/note supplied by the agent at action time
    status        text        not null default 'pending',  -- pending | processing | success | failed
    result_note   text,
    created_at    timestamptz not null default now(),
    completed_at  timestamptz
);

create index if not exists idx_pending_actions_status
    on public.pending_actions (status, created_at);

-- Contact-reporter conversation thread (up to 5 messages per report).
-- sender: 'agent' | 'reporter'
create table if not exists public.contact_messages (
    id            bigint generated always as identity primary key,
    report_id     text        not null references public.reports (report_id) on delete cascade,
    sender        text        not null,  -- 'agent' or 'reporter'
    sender_name   text        not null,
    body          text        not null,
    created_at    timestamptz not null default now()
);

create index if not exists idx_contact_messages_report
    on public.contact_messages (report_id, created_at);

-- -----------------------------------------------------------------------
-- Incremental alterations (safe to re-run; each is idempotent via IF NOT EXISTS
-- or DO $$ EXCEPTION blocks).
-- -----------------------------------------------------------------------

-- Add reason column to pending_actions (stores agent-supplied reason text).
DO $$ BEGIN
    ALTER TABLE public.pending_actions ADD COLUMN reason text;
EXCEPTION
    WHEN duplicate_column THEN NULL;
END $$;

-- Add processing status to pending_actions if the check constraint exists
-- (older installs may not have one; this is a no-op if there is none).
-- Just a comment — no constraint was added in the original migration.
