# MATCH-2 measurements on the kept full ingest (Phase 4 gate)

Date: 2026-11-14. Plan: `dev/plans/2026-11-13-product-match-rules-plan.md` Phase 4. Design: `dev/plans/2026-11-13-product-match-rules-design.md` section 13 (measurements and thresholds) and section 5.3 (the earlier numbers).

**Gate result: FAIL.** Every single-product, package and saved-search row passes. Every row of the limit rule (50 one-value product conditions plus 50 one-value package conditions, no ecosystem, under `or`) fails, and so does M6 (50 products under `or`). Phase 4 is deferred until Sam decides the remedy (plan Task 4.3).

## Method

- **Where:** the kept full ingest, PostgreSQL 18.4, 2,628,861 CVEs, at migration 61, read-only: the connection sets `default_transaction_read_only=on`, the harness checks it, and every statement runs in `BEGIN READ ONLY` with `SET LOCAL statement_timeout = '60s'`. Its three check indexes match the expressions the code emits (`check.CPEIndexExpr`, `check.CNANameIndexExpr`, `ecosystem.FoldedNameSQL`).
- **M8's full activation:** a disposable copy restored from the kept ingest's complete backup (2,619,718 CVEs, migrated to 62 and analysed), never the kept container. The copy is kept for Task 5.5.
- **Statements:** production code builds them. `candidateQuery` (the evaluator's statement) for realtime (one CVE, `CVE-2024-26581`), batch (the 5,000 most recently modified CVE IDs) and dry-run (no candidate IDs); the saved-search row rebuilds `store.ExecuteDSLQuery`'s first page. Rules pass `dsl.Validate` and `dsl.Compile` first.
- **Timing:** `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` three times. "First run" is run 1; "warm" is the mean of runs 2 and 3. A row's compared figure is warm planning plus execution, except where its threshold says "first run". Caches were never dropped.
- **Harness:** `internal/alert/kept_ingest_measure_test.go` and `internal/alert/kept_ingest_activation_test.go`, build tag `keptingest`, so the normal suite never runs them.
- **Both containers have Docker's default 64 MB `/dev/shm`.** PostgreSQL keeps a parallel hash's shared memory there. Rows marked "error" failed with `could not resize shared memory segment ... No space left on device`. No compose file in `docker/` sets `shm_size`, so a default deployment has the same limit. That is being raised with Sam separately and is not part of this change.

## Inputs

**Products** (the 50 with the most vulnerable CPE rows that the value parser accepts; none of the first 80 was refused): `linux:linux_kernel`, `cisco:ios`, `juniper:junos`, `mozilla:firefox`, `google:chrome`, `samsung:android`, `cisco:ios_xe`, `google:android`, `mozilla:seamonkey`, `opera:opera_browser`, `sun:jre`, `microsoft:windows_10`, `apple:safari`, `apple:mac_os_x`, `adobe:flash_player`, `php:php`, `debian:debian_linux`, `sun:jdk`, `apple:itunes`, `mozilla:thunderbird`, `cisco:adaptive_security_appliance_software`, `canonical:ubuntu_linux`, `liferay:digital_experience_platform`, `apple:iphone_os`, `adobe:acrobat`, `sun:opensolaris`, `adobe:commerce`, `fedoraproject:fedora`, `microsoft:windows_server_2016`, `microsoft:windows_server_2012`, `coollabs:coolify`, `adobe:acrobat_reader`, `microsoft:windows_server_2008`, `ibm:websphere_application_server`, `checkmk:checkmk`, `oracle:mysql`, `vmware:esxi`, `apache:tomcat`, `juniper:junos_os_evolved`, `microsoft:windows_10_22h2`, `microsoft:windows_10_21h2`, `moodle:moodle`, `oracle:jre`, `oracle:jdk`, `gitlab:gitlab`, `ffmpeg:ffmpeg`, `phpmyadmin:phpmyadmin`, `adobe:coldfusion`, `microsoft:windows_10_1809`, `mozilla:bugzilla`.

**Packages** (the 50 most common folded package names): `linux`, `kernel`, `linux-azure`, `linux-gcp`, `linux-fips`, `linux-riscv`, `linux-realtime`, `linux-aws`, `linux-aws-fips`, `linux-azure-fips`, `linux-oracle`, `linux-gcp-fips`, `linux-azure-fde`, `linux-gke`, `chromium`, `linux-raspi`, `linux-hwe-edge`, `linux-gkeop`, `linux-ibm`, `linux-lts`, `linux-kvm`, `linux-raspi-realtime`, `linux-hwe`, `linux-nvidia`, `linux-intel-iot-realtime`, `linux-bluefield`, `linux-raspi2`, `linux-lowlatency`, `linux-oem`, `linux-gke-4.15`, `linux-azure-edge`, `linux-aws-5.0`, `linux-oracle-5.0`, `linux-gcp-5.3`, `linux-azure-5.3`, `linux-oracle-5.3`, `linux-aws-5.3`, `linux-oem-5.6`, `linux-hwe-5.8`, `linux-riscv-5.8`, `linux-gkeop-5.4`, `linux-gke-5.4`, `linux-oem-5.10`, `linux-aws-5.8`, `linux-oracle-5.8`, `linux-gcp-5.8`, `linux-azure-5.8`, `linux-hwe-5.11`, `linux-azure-5.11`, `linux-oracle-5.11`.

The package list is the worst case section 13 asks for: 49 of the 50 are Linux kernel package names (Debian, Ubuntu and their kernel flavours) and the other is `chromium`; the kernel names sit on 19,399 (`linux-oracle-5.11`) to 131,545 (`linux`) package rows. A rule that names common packages with no ecosystem meets this cost; one that names its packages' ecosystem does not (M7a to M7c).

## Results (design section 13)

Thresholds: realtime 5 ms; batch 3 s; dry-run and saved search 5 s; package `eq` with no ecosystem 5 s on the first run; package `contains` with no ecosystem no slower than the form before this work; activation 7 minutes. Rows marked "information only" have none: the limit rule under `and` can stop at its first empty set, so section 13 applies the thresholds to `or`.

| # | Measurement | Statement shape | Args | First run plan / exec (ms) | Warm plan / exec (ms) | Rows | Plan notes | Threshold | Result |
|---|---|---|---|---|---|---|---|---|---|
| M1a | linux:linux_kernel, and | realtime | 20 | 6.09 / 1.07 | 0.49 / 0.12 | 1 |  | warm <= 5 ms | pass; first run over threshold |
| M1b | linux:linux_kernel or in_cisa_kev | realtime | 21 | 0.43 / 1.16 | 0.43 / 0.15 | 1 | hashed SubPlan | warm <= 5 ms | pass |
| M2a | linux:linux_kernel, and | batch 5,000 | 20 | 26.47 / 33.65 | 25.79 / 4.98 | 0 |  | warm <= 3000 ms | pass |
| M2b | linux:linux_kernel or in_cisa_kev | batch 5,000 | 21 | 33.78 / 64.41 | 26.54 / 38.51 | 0 | hashed SubPlan | warm <= 3000 ms | pass |
| M2c | nodejs:node.js, and | batch 5,000 | 41 | 26.13 / 11.79 | 26.93 / 5.39 | 0 |  | warm <= 3000 ms | pass |
| M3a | nodejs:node.js and severity critical/high | dry-run | 39 | 0.74 / 33.97 | 0.67 / 2.86 | 146 |  | warm <= 5000 ms | pass |
| M3b | nodejs:node.js alone | dry-run | 38 | 0.63 / 3.05 | 0.63 / 3.51 | 249 |  | warm <= 5000 ms | pass |
| M3c | nodejs:node.js or in_cisa_kev | dry-run | 39 | 0.63 / 1430.26 | 0.62 / 408.51 | 2026 | hashed SubPlan; seq scan: cves | warm <= 5000 ms | pass |
| M3d | linux:linux_kernel alone | dry-run | 17 | 0.39 / 391.31 | 0.41 / 189.08 | 5001 |  | warm <= 5000 ms | pass |
| M3e | linux:linux_kernel or in_cisa_kev | dry-run | 18 | 0.38 / 345.51 | 0.53 / 287.48 | 5001 | hashed SubPlan; seq scan: cves | warm <= 5000 ms | pass |
| M4 | linux:linux_kernel | saved search, page of 50 | 17 | 2.36 / 228.81 | 0.43 / 177.96 | 51 |  | warm <= 5000 ms | pass |
| M5a | limit rule, or | realtime | 985 | 23.95 / 6.14 | 18.61 / 4.71 | 1 | hashed SubPlan | warm <= 5 ms | FAIL |
| M5b | limit rule, or | dry-run | 834 | 0.00 / 0.00 | 0.00 / 0.00 | 0 | error: *pgconn.PgError | warm <= 5000 ms | FAIL (error) |
| M5c | limit rule, or | batch 5,000 | 985 | 0.00 / 0.00 | 0.00 / 0.00 | 0 | error: *pgconn.PgError | warm <= 3000 ms | FAIL (error) |
| M5d | limit rule, and (information) | realtime | 985 | 158.62 / 4.45 | 169.48 / 5.31 | 0 |  | information only | - |
| M5e | limit rule, and (information) | dry-run | 834 | 220.80 / 8720.36 | 246.68 / 8523.59 | 0 |  | information only | - |
| M5f | limit rule, and (information) | batch 5,000 | 985 | 2186.64 / 7871.58 | 2274.36 / 8096.60 | 0 |  | information only | - |
| M6 | 50 products, or | dry-run | 734 | 14.35 / 16810.19 | 12.35 / 16174.24 | 5001 | hashed SubPlan; seq scan: cves | warm <= 5000 ms | FAIL |
| M7a | npm, package in 50 names | dry-run | 2 | 0.50 / 626.48 | 0.48 / 489.82 | 0 |  | warm <= 5000 ms | pass |
| M7b | Debian, package eq openssl | dry-run | 3 | 0.44 / 62.72 | 0.32 / 8.64 | 395 |  | warm <= 5000 ms | pass |
| M7c | package eq openssl, no ecosystem | dry-run | 2 | 0.33 / 159.99 | 0.32 / 22.99 | 2037 |  | first run <= 5000 ms | pass |
| M7d-old | package contains lodash, no ecosystem, per-row EXISTS (before) | dry-run | 1 | 0.26 / 1176.85 | 0.29 / 1200.12 | 135 | seq scan: cve_affected_packages | information only | - |
| M7d | package contains lodash, no ecosystem, set form | dry-run | 1 | 0.30 / 1179.73 | 0.29 / 1170.29 | 135 | seq scan: cve_affected_packages | not slower than M7d-old | pass (not slower than M7d-old) |

M8 read-only estimate (kept ingest): 1 pages of 1000 IDs, 0 matches, 9s read time, stopped by error (*fmt.wrapError <- *pgconn.PgError).

M8 full activation (disposable copy): the limit rule under `or` failed on its first page after 10 s, with the shared-memory error above; the rule was set to `status=error` and no events were written. Threshold 7 minutes: **FAIL**.

## Smaller limits (read-only sweep, for the gate decision)

The same harness, same inputs: the K largest products and the K most common packages, one value per condition, under `or`. The last two rows run the full limit rule with parallel query off (`SET LOCAL max_parallel_workers_per_gather = 0`), which avoids the shared-memory error and shows the statement's own serial cost.

| # | Measurement | Statement shape | Args | First run plan / exec (ms) | Warm plan / exec (ms) | Rows | Plan notes | Threshold | Result |
|---|---|---|---|---|---|---|---|---|---|
| S5-rt | 5 products + 5 packages, or | realtime | 95 | 5.67 / 0.54 | 1.52 / 0.33 | 1 | hashed SubPlan | warm <= 5 ms | pass; first run over threshold |
| S5-dry | 5 products + 5 packages, or | dry-run | 79 | 1.38 / 3449.61 | 1.57 / 3532.88 | 5001 | hashed SubPlan; seq scan: cves | warm <= 5000 ms | pass |
| S5-batch | 5 products + 5 packages, or | batch 5,000 | 95 | 208.18 / 926.89 | 200.43 / 891.60 | 4485 | hashed SubPlan | warm <= 3000 ms | pass |
| S10-rt | 10 products + 10 packages, or | realtime | 193 | 2.80 / 0.93 | 2.67 / 0.79 | 1 | hashed SubPlan | warm <= 5 ms | pass |
| S10-dry | 10 products + 10 packages, or | dry-run | 162 | 2.65 / 9972.61 | 2.78 / 10928.22 | 5001 | hashed SubPlan; seq scan: cves | warm <= 5000 ms | FAIL |
| S10-batch | 10 products + 10 packages, or | batch 5,000 | 193 | 0.00 / 0.00 | 0.00 / 0.00 | 0 | error: *pgconn.PgError | warm <= 3000 ms | FAIL (error) |
| S15-rt | 15 products + 15 packages, or | realtime | 295 | 6.87 / 2.16 | 5.75 / 2.38 | 1 | hashed SubPlan | warm <= 5 ms | FAIL |
| S15-dry | 15 products + 15 packages, or | dry-run | 249 | 4.39 / 12629.77 | 3.74 / 14327.43 | 5001 | hashed SubPlan; seq scan: cves | warm <= 5000 ms | FAIL |
| S15-batch | 15 products + 15 packages, or | batch 5,000 | 295 | 0.00 / 0.00 | 0.00 / 0.00 | 0 | error: *pgconn.PgError | warm <= 3000 ms | FAIL (error) |
| S25-rt | 25 products + 25 packages, or | realtime | 499 | 8.40 / 2.09 | 7.10 / 2.13 | 1 | hashed SubPlan | warm <= 5 ms | FAIL |
| S25-dry | 25 products + 25 packages, or | dry-run | 423 | 5.98 / 25848.79 | 6.10 / 26437.40 | 5001 | hashed SubPlan; seq scan: cves | warm <= 5000 ms | FAIL |
| S25-batch | 25 products + 25 packages, or | batch 5,000 | 499 | 0.00 / 0.00 | 0.00 / 0.00 | 0 | error: *pgconn.PgError | warm <= 3000 ms | FAIL (error) |
| S10-products | 10 products, or | dry-run | 142 | 2.87 / 1549.36 | 3.63 / 936.87 | 5001 | hashed SubPlan; seq scan: cves | warm <= 5000 ms | pass |
| S25-products | 25 products, or | dry-run | 373 | 7.29 / 2207.64 | 5.98 / 2677.26 | 5001 | hashed SubPlan; seq scan: cves | warm <= 5000 ms | pass |
| S50-dry-serial | limit rule, or, parallel query off | dry-run | 834 | 13.30 / 30528.88 | 13.70 / 27638.67 | 5001 | hashed SubPlan; seq scan: cves | warm <= 5000 ms | FAIL |
| S50-batch-serial | limit rule, or, parallel query off | batch 5,000 | 985 | 2505.63 / 22645.63 | 2403.39 / 15262.34 | 4564 | hashed SubPlan | warm <= 3000 ms | FAIL |

## What the numbers say

- **One product, and the package forms with an ecosystem, are fast.** Realtime under 1 ms warm (M1), batch under 70 ms (M2), Node dry-run 3.5 ms (M3a, against 11.1 s in the per-row form the design started from). The design's section 5.3 rows hold.
- **Package conditions with no ecosystem cost the most.** A package set with no ecosystem gathers every row of that name in every ecosystem; for kernel package names that is from 19,399 rows (`linux-oracle-5.11`) to 131,545 rows on 54,832 CVEs (`linux`) per condition. 5 such conditions with 5 products take 3.5 s dry-run (S5-dry); 10 and 10 take 10.9 s (S10-dry), and the batch statement already needs more shared memory than 64 MB (S10-batch).
- **Products are cheaper per condition:** 25 of the largest products under `or` take 2.7 s dry-run (S25-products); 50 take 16.2 s (M6).
- **Realtime planning grows with the number of set conditions,** about 0.15 to 0.2 ms each: 20 set conditions plan in 2.7 ms (S10-rt), 30 in 5.8 ms (S15-rt), 100 in 18.6 ms (M5a).
- **Serial execution is not a way out:** with parallel query off, the full limit rule takes 27.6 s dry-run and 17.7 s batch (S50-*-serial).
- **Dry-run under `or` builds each set in full** (a hashed SubPlan) before it reads `cves`, so its cost follows the total size of the sets, not the 5,001-row limit.

## Failing rows

| Row | Measured (warm) | Threshold |
|---|---|---|
| M5a limit rule `or`, realtime | 23.3 ms (18.6 ms planning) | 5 ms |
| M5b limit rule `or`, dry-run | shared-memory error; 27.6 s serial | 5 s |
| M5c limit rule `or`, batch 5,000 | shared-memory error; 17.7 s serial | 3 s |
| M6 50 products `or`, dry-run | 16.2 s (SubPlan hashed) | 5 s |
| M8 limit rule `or`, full activation | shared-memory error on page 1 | 7 minutes |

Flagged, not failing: M1a's first run took 7.2 ms (6.1 ms planning) against 5 ms; warm 0.6 ms.

## The same content as two set conditions (read-only, for the gate decision)

`TestKeptIngestMergedForms`: the limit rule's 50 products as one `affected.cpe_product in` condition and its 50 packages as one `affected.package in` condition, under `or`, with JIT on (the server default) and off (`SET LOCAL jit = off`). The compiler emits this form today for a list. It is still two `IN` sets joined by `OR`, so each is a hashed SubPlan; a single `IN (... UNION ALL ...)` over every set, which a separate read-only test on the copy found to plan as a merge semi-join (101 ms, then 55 ms, for the 50 package names alone), is not a form the compiler emits and is not measured here.

| # | Measurement | Statement shape | Args | First run plan / exec (ms) | Warm plan / exec (ms) | Rows | Plan notes | Threshold | Result |
|---|---|---|---|---|---|---|---|---|---|
| G-rt | product in 50 or package in 50 | realtime | 740 | 17.23 / 0.70 | 10.71 / 0.68 | 1 | hashed SubPlan | warm <= 5 ms | FAIL |
| G-dry | product in 50 or package in 50 | dry-run | 736 | 0.00 / 0.00 | 0.00 / 0.00 | 0 | error: *pgconn.PgError | warm <= 5000 ms | FAIL (error) |
| G-batch | product in 50 or package in 50 | batch 5,000 | 740 | 60.88 / 1500.63 | 115.42 / 1612.79 | 4564 | hashed SubPlan | warm <= 3000 ms | pass |
| G-rt-nojit | product in 50 or package in 50, jit off | realtime | 740 | 63.65 / 1.47 | 30.01 / 2.50 | 1 | hashed SubPlan | warm <= 5 ms | FAIL |
| G-dry-nojit | product in 50 or package in 50, jit off | dry-run | 736 | 0.00 / 0.00 | 0.00 / 0.00 | 0 | error: *pgconn.PgError | warm <= 5000 ms | FAIL (error) |
| G-batch-nojit | product in 50 or package in 50, jit off | batch 5,000 | 740 | 52.56 / 441.62 | 51.31 / 454.73 | 4564 | hashed SubPlan | warm <= 3000 ms | pass |
| G-products-dry | product in 50 (one condition) | dry-run | 734 | 10.46 / 9229.15 | 9.99 / 8036.55 | 5001 |  | warm <= 5000 ms | FAIL |
| G-products-dry-nojit | product in 50 (one condition), jit off | dry-run | 734 | 9.85 / 3846.99 | 9.91 / 3908.36 | 5001 |  | warm <= 5000 ms | pass |

Reading: batch passes in this form (1.7 s; 0.51 s with JIT off), against 17.7 s serially for 100 one-value conditions. Dry-run of products and packages together still fails with the shared-memory error. 50 products in one condition take 8.0 s dry-run with JIT on and 3.9 s with it off, so JIT costs about 4 s there. Realtime still fails on planning (10.7 ms): the cost is the number of OR-ed range and name terms inside the product set, which merging conditions does not reduce.
