-- Drops alert_rules.fire_on_non_material_changes. No code read the flag, and
-- built as specified it would mostly re-alert on noise such as daily EPSS moves.
-- Reasons: dev/plans/2026-11-14-remove-fire-on-non-material-changes-design.md

ALTER TABLE alert_rules DROP COLUMN IF EXISTS fire_on_non_material_changes;
