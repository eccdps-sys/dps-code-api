-- 002_contact_messages.sql
-- Run once in the Supabase SQL editor.
-- Stores the agent ↔ reporter back-and-forth for "contact_reporter" flows.
-- Max 5 messages per report enforced at the API layer.

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
