-- Restores alert_rules.fire_on_non_material_changes as migration 000015 created it.
-- Every rule gets the column default, false: the values the up migration dropped are not kept.

ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS fire_on_non_material_changes BOOL NOT NULL DEFAULT false;
