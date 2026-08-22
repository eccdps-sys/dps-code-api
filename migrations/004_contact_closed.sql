-- 004_contact_closed.sql
-- Adds agent-controlled conversation close state to the reports table.
-- Run once in the Supabase SQL editor.

DO $$ BEGIN
    ALTER TABLE public.reports ADD COLUMN contact_closed     boolean     NOT NULL DEFAULT false;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE public.reports ADD COLUMN contact_closed_at  timestamptz;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE public.reports ADD COLUMN contact_closed_by  text;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;
