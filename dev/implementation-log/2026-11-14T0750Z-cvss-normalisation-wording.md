# CVSS vector normalisation: documents describe the sort the hash uses

## What was built

| Feature | Files | Description |
|---|---|---|
| Docs | `PLAN.md` §5.3, `CLAUDE.md`, `AGENTS.md` | The material-hash rules now say CVSS metrics are sorted lexicographically after the version prefix, as hash input only. They said the vector was re-serialized in the CVSS spec's metric order, "not alphabetical". |
| Comments | `internal/merge/hash.go` | `ComputeMaterialHash` and `normalizeCVSSVector` comments describe the sort, not spec order. |

## Key decisions

- **Change the documents, not the code.** The rule exists so that one vector listed in two metric orders hashes the same; any fixed order does that, and the sort does. `normalizeCVSSVector` works on a copy of the fields passed to the hash, so stored vectors keep the source's order. Switching to spec order would change the `material_hash` of every CVE with a vector on its next merge, which re-fires every matching rule once, for no difference in behaviour afterwards. Found by the MATCH-2 `/plan-check` (product-match-rules plan, Discoveries).

## Quality checks

- Comment and document changes only; no tests run for this commit.
