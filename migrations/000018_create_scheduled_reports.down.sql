-- migrate:no-transaction

DROP INDEX CONCURRENTLY IF EXISTS report_channels_channel_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS report_channels_org_id_idx;
DROP TABLE IF EXISTS report_channels;

DROP INDEX CONCURRENTLY IF EXISTS scheduled_reports_next_run_idx;
DROP INDEX CONCURRENTLY IF EXISTS scheduled_reports_name_uq;
DROP INDEX CONCURRENTLY IF EXISTS scheduled_reports_org_id_idx;
DROP TABLE IF EXISTS scheduled_reports;
