-- migrate:no-transaction
-- DROP INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).

DROP INDEX CONCURRENTLY IF EXISTS notification_deliveries_created_at_idx;
DROP INDEX CONCURRENTLY IF EXISTS notification_deliveries_rule_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS notification_deliveries_channel_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS notification_deliveries_org_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS notification_deliveries_processing_idx;
DROP INDEX CONCURRENTLY IF EXISTS notification_deliveries_claim_idx;
DROP INDEX CONCURRENTLY IF EXISTS uq_notification_deliveries_pending;

DROP INDEX CONCURRENTLY IF EXISTS alert_rule_channels_channel_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS alert_rule_channels_org_id_idx;

DROP INDEX CONCURRENTLY IF EXISTS notification_channels_name_uq;
DROP INDEX CONCURRENTLY IF EXISTS notification_channels_active_idx;
DROP INDEX CONCURRENTLY IF EXISTS notification_channels_org_id_idx;

DROP TABLE IF EXISTS notification_deliveries;
DROP TABLE IF EXISTS alert_rule_channels;
DROP TABLE IF EXISTS notification_channels;
