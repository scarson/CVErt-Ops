-- migrate:no-transaction
-- Symmetric with up migration (pitfall 11.2).

DROP TABLE IF EXISTS job_queue;
