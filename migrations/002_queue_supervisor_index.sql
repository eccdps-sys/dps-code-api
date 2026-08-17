-- 002_queue_supervisor_index.sql
-- Run once in the Supabase SQL editor.
-- Adds an index to speed up the dual operator/supervisor queue filtering
-- which joins pending_actions with reports on is_supervisor.

-- Index on reports.is_supervisor so the join filter is fast.
create index if not exists idx_reports_is_supervisor
    on public.reports (is_supervisor);

-- Composite index on pending_actions covering the queue pickup query:
-- status = 'pending', ordered by created_at, joined to reports.
create index if not exists idx_pending_actions_status_created
    on public.pending_actions (status, created_at asc)
    where status = 'pending';
