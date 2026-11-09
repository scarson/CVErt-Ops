-- ABOUTME: Masks channel audit records written before masking covered every config field.
-- ABOUTME: Applies the rule in audit.RedactChannelConfig to old_state and new_state.

-- audit_log has FORCE ROW LEVEL SECURITY, so a migration role that is not a
-- superuser matches no rows without this setting. The migrate command runs
-- each statement in autocommit, so a transaction-scoped setting would not
-- reach the updates. Statement text may not contain a semicolon except as a
-- terminator, because the migrate command splits the file on them.
SET app.bypass_rls = 'on';

-- Header names stay and every header value is masked. The already reduced url
-- and lists of addresses are shown as they are. Every other field is masked
-- whole because its shape cannot be trusted.
-- A config key could replace name or type in these records, so each is kept
-- only when it looks genuine: type must be a channel type and name must match
-- entity_name. old_state also keeps a name when new_state matches entity_name,
-- which is how a rename looks.
-- The WHERE clause excludes states that are not objects, which jsonb_each rejects.
UPDATE audit_log
SET old_state = COALESCE((
    SELECT jsonb_object_agg(field.key, CASE
        WHEN lower(field.key) IN ('custom_headers', 'headers') THEN
            CASE WHEN jsonb_typeof(field.value) = 'object' THEN COALESCE(
                (SELECT jsonb_object_agg(header.key, to_jsonb('[REDACTED]'::text))
                 FROM jsonb_each(field.value) AS header),
                '{}'::jsonb)
            ELSE to_jsonb('[REDACTED]'::text) END
        WHEN field.key = 'name' AND (field.value = to_jsonb(entity_name) OR new_state->'name' = to_jsonb(entity_name)) THEN field.value
        WHEN field.key = 'type' AND field.value IN ('"webhook"'::jsonb, '"email"'::jsonb) THEN field.value
        WHEN field.key = 'url' AND jsonb_typeof(field.value) = 'string' THEN field.value
        WHEN field.key = 'recipients' AND jsonb_typeof(field.value) = 'array' THEN
            CASE WHEN NOT EXISTS (
                SELECT 1 FROM jsonb_array_elements(field.value) AS recipient
                WHERE jsonb_typeof(recipient) <> 'string' OR recipient #>> '{}' NOT LIKE '%@%'
            ) THEN field.value
            ELSE to_jsonb('[REDACTED]'::text) END
        ELSE to_jsonb('[REDACTED]'::text)
    END)
    FROM jsonb_each(old_state) AS field
), '{}'::jsonb)
WHERE entity_type = 'channel'
  AND jsonb_typeof(old_state) = 'object';

UPDATE audit_log
SET new_state = COALESCE((
    SELECT jsonb_object_agg(field.key, CASE
        WHEN lower(field.key) IN ('custom_headers', 'headers') THEN
            CASE WHEN jsonb_typeof(field.value) = 'object' THEN COALESCE(
                (SELECT jsonb_object_agg(header.key, to_jsonb('[REDACTED]'::text))
                 FROM jsonb_each(field.value) AS header),
                '{}'::jsonb)
            ELSE to_jsonb('[REDACTED]'::text) END
        WHEN field.key = 'name' AND field.value = to_jsonb(entity_name) THEN field.value
        WHEN field.key = 'type' AND field.value IN ('"webhook"'::jsonb, '"email"'::jsonb) THEN field.value
        WHEN field.key = 'url' AND jsonb_typeof(field.value) = 'string' THEN field.value
        WHEN field.key = 'recipients' AND jsonb_typeof(field.value) = 'array' THEN
            CASE WHEN NOT EXISTS (
                SELECT 1 FROM jsonb_array_elements(field.value) AS recipient
                WHERE jsonb_typeof(recipient) <> 'string' OR recipient #>> '{}' NOT LIKE '%@%'
            ) THEN field.value
            ELSE to_jsonb('[REDACTED]'::text) END
        ELSE to_jsonb('[REDACTED]'::text)
    END)
    FROM jsonb_each(new_state) AS field
), '{}'::jsonb)
WHERE entity_type = 'channel'
  AND jsonb_typeof(new_state) = 'object';

RESET app.bypass_rls;
