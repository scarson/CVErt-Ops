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

## After the remedy Sam chose (2026-11-14)

Two changes: under `or`, every set condition is one `cves.cve_id IN (... UNION ALL ...)` and the evaluator's candidate statement runs with `SET LOCAL jit = off` (`7ad8080`); with candidate IDs, a product set matches its CPE prefixes and CNA names against bound arrays (`fe0e32f`). Every evaluator-shaped row below runs with JIT off, as `queryCandidates` does; the saved-search row (M4) keeps the server default, as `ExecuteDSLQuery` does.

| # | Measurement | Statement shape | Args | First run plan / exec (ms) | Warm plan / exec (ms) | Rows | Plan notes | Threshold | Result |
|---|---|---|---|---|---|---|---|---|---|
| M1a | linux:linux_kernel, and | realtime | 12 | 2.12 / 0.25 | 0.38 / 0.14 | 1 |  | warm <= 5 ms | pass |
| M1b | linux:linux_kernel or in_cisa_kev | realtime | 13 | 0.41 / 0.23 | 0.34 / 0.16 | 1 | hashed SubPlan | warm <= 5 ms | pass |
| M2a | linux:linux_kernel, and | batch 5,000 | 12 | 27.44 / 557.10 | 26.48 / 478.07 | 0 | seq scan: cve_cna_affected, cve_cpe_matches | warm <= 3000 ms | pass |
| M2b | linux:linux_kernel or in_cisa_kev | batch 5,000 | 13 | 25.95 / 461.24 | 26.62 / 479.69 | 0 | hashed SubPlan; seq scan: cve_cna_affected, cve_cpe_matches | warm <= 3000 ms | pass |
| M2c | nodejs:node.js, and | batch 5,000 | 12 | 25.68 / 114.09 | 26.33 / 115.75 | 0 | seq scan: cve_cna_affected, cve_cpe_matches | warm <= 3000 ms | pass |
| M3a | nodejs:node.js and severity critical/high | dry-run | 39 | 0.90 / 6.35 | 0.67 / 2.85 | 146 |  | warm <= 5000 ms | pass |
| M3b | nodejs:node.js alone | dry-run | 38 | 0.62 / 3.23 | 0.62 / 2.97 | 249 |  | warm <= 5000 ms | pass |
| M3c | nodejs:node.js or in_cisa_kev | dry-run | 39 | 0.57 / 400.34 | 0.58 / 372.12 | 2026 | hashed SubPlan; seq scan: cves | warm <= 5000 ms | pass |
| M3d | linux:linux_kernel alone | dry-run | 17 | 0.40 / 161.50 | 0.40 / 156.49 | 5001 |  | warm <= 5000 ms | pass |
| M3e | linux:linux_kernel or in_cisa_kev | dry-run | 18 | 0.36 / 213.57 | 0.38 / 250.18 | 5001 | hashed SubPlan; seq scan: cves | warm <= 5000 ms | pass |
| M4 | linux:linux_kernel | saved search, page of 50 | 17 | 0.76 / 156.66 | 0.43 / 160.82 | 51 |  | warm <= 5000 ms | pass |
| M5a | limit rule, or | realtime | 162 | 6.79 / 22.45 | 6.47 / 19.94 | 1 |  | warm <= 5 ms | FAIL |
| M5b | limit rule, or | dry-run | 834 | 14.90 / 10910.94 | 16.34 / 10984.17 | 5001 | seq scan: cves | warm <= 5000 ms | FAIL |
| M5c | limit rule, or | batch 5,000 | 162 | 814.17 / 2460.32 | 793.87 / 2371.01 | 4564 | seq scan: cve_cna_affected | warm <= 3000 ms | FAIL |
| M5d | limit rule, and (information) | realtime | 701 | 191.42 / 3.87 | 186.78 / 4.60 | 0 |  | information only | - |
| M5e | limit rule, and (information) | dry-run | 834 | 214.78 / 1099.93 | 225.12 / 1109.81 | 0 |  | information only | - |
| M5f | limit rule, and (information) | batch 5,000 | 701 | 2287.43 / 945.27 | 2311.62 / 941.05 | 0 | seq scan: cve_cna_affected, cve_cpe_matches | information only | - |
| M6 | 50 products, or | dry-run | 734 | 12.27 / 570.73 | 12.73 / 573.15 | 5001 | SubPlan NOT hashed | warm <= 5000 ms | pass (not hashed; within threshold) |
| M7a | npm, package in 50 names | dry-run | 2 | 0.53 / 581.65 | 0.50 / 499.42 | 0 |  | warm <= 5000 ms | pass |
| M7b | Debian, package eq openssl | dry-run | 3 | 0.46 / 20.05 | 0.37 / 8.60 | 395 |  | warm <= 5000 ms | pass |
| M7c | package eq openssl, no ecosystem | dry-run | 2 | 0.35 / 40.20 | 0.33 / 24.43 | 2037 |  | first run <= 5000 ms | pass |
| M7d-old | package contains lodash, no ecosystem, per-row EXISTS (before) | dry-run | 1 | 0.25 / 1276.54 | 0.31 / 1293.75 | 135 | seq scan: cve_affected_packages | information only | - |
| M7d | package contains lodash, no ecosystem, set form | dry-run | 1 | 0.45 / 1308.27 | 0.29 / 1241.78 | 135 | seq scan: cve_affected_packages | not slower than M7d-old | pass (not slower than M7d-old) |

M8 read-only estimate (kept ingest): 1421 pages of 1000 IDs, 33361 matches, 12m2s read time, stopped by error (*fmt.wrapError <- *pgconn.PgError).

Sweep after the merge and JIT off, before the array form (same inputs; for the limit choice):

| # | Measurement | Statement shape | Args | First run plan / exec (ms) | Warm plan / exec (ms) | Rows | Plan notes | Threshold | Result |
|---|---|---|---|---|---|---|---|---|---|
| S5-rt | 5 products + 5 packages, or | realtime | 95 | 5.02 / 0.45 | 1.49 / 0.29 | 1 |  | warm <= 5 ms | pass; first run over threshold |
| S5-dry | 5 products + 5 packages, or | dry-run | 79 | 2.07 / 1660.22 | 1.36 / 1685.66 | 5001 | seq scan: cves | warm <= 5000 ms | pass |
| S5-batch | 5 products + 5 packages, or | batch 5,000 | 95 | 207.65 / 394.85 | 379.09 / 1328.93 | 4485 |  | warm <= 3000 ms | pass |
| S10-rt | 10 products + 10 packages, or | realtime | 193 | 5.77 / 69.05 | 3.57 / 32.58 | 1 |  | warm <= 5 ms | FAIL |
| S10-dry | 10 products + 10 packages, or | dry-run | 162 | 2.55 / 5194.42 | 4.00 / 7263.74 | 5001 | seq scan: cves | warm <= 5000 ms | FAIL |
| S10-batch | 10 products + 10 packages, or | batch 5,000 | 193 | 436.07 / 786.51 | 474.88 / 1106.10 | 4562 |  | warm <= 3000 ms | pass |
| S15-rt | 15 products + 15 packages, or | realtime | 295 | 7.30 / 46.37 | 6.00 / 31.80 | 1 |  | warm <= 5 ms | FAIL |
| S15-dry | 15 products + 15 packages, or | dry-run | 249 | 3.90 / 4932.91 | 3.65 / 4312.54 | 5001 | seq scan: cves | warm <= 5000 ms | pass |
| S15-batch | 15 products + 15 packages, or | batch 5,000 | 295 | 694.32 / 1163.04 | 675.13 / 1120.74 | 4563 |  | warm <= 3000 ms | pass |
| S25-rt | 25 products + 25 packages, or | realtime | 499 | 7.92 / 32.67 | 7.70 / 26.56 | 1 |  | warm <= 5 ms | FAIL |
| S25-dry | 25 products + 25 packages, or | dry-run | 423 | 6.29 / 6225.98 | 6.96 / 6164.42 | 5001 | seq scan: cves | warm <= 5000 ms | FAIL |
| S25-batch | 25 products + 25 packages, or | batch 5,000 | 499 | 1332.82 / 1893.59 | 1135.56 / 1663.73 | 4564 |  | warm <= 3000 ms | pass; first run over threshold |
| S10-products | 10 products, or | dry-run | 142 | 2.12 / 323.76 | 2.24 / 298.71 | 5001 |  | warm <= 5000 ms | pass |
| S25-products | 25 products, or | dry-run | 373 | 5.35 / 417.83 | 5.24 / 407.52 | 5001 |  | warm <= 5000 ms | pass |
| S50-dry-serial | limit rule, or, parallel query off | dry-run | 834 | 13.52 / 12595.21 | 16.78 / 13122.20 | 5001 | seq scan: cves | warm <= 5000 ms | FAIL |
| S50-batch-serial | limit rule, or, parallel query off | batch 5,000 | 985 | 2689.40 / 3734.69 | 2657.31 / 3607.04 | 4564 |  | warm <= 3000 ms | FAIL |

### Reading

- **Fixed:** 50 products under `or` (M6), 16.2 s to 0.6 s. Planning of candidate statements no longer grows with the number of products: the limit rule's realtime planning fell from 18.6 ms to 6.5 ms and its arguments from 985 to 162.
- **Still failing:** M5a realtime 26.4 ms (6.5 ms planning, 19.9 ms execution) against 5 ms; M5b dry-run 11.0 s against 5 s (no candidate IDs, so the array form does not apply; the cost is the 50 kernel package sets with no ecosystem, hashed in full); M5c batch 3.2 s (0.8 s planning) against 3 s; M8 read-only estimate stopped by the shared-memory error at page 1,422 of about 2,629 after 12 minutes, so a full activation would take about 22 minutes against 7.
- **Regression, still within thresholds:** single-product batch rows M2a to M2c rose from about 30 ms to 140 to 505 ms. With 5,000 candidate IDs and the array form, the planner chooses parallel sequential scans of `cve_cpe_matches` (about 1.08 M rows filtered out) and `cve_cna_affected` (about 685 K) with `cve_id = ANY(...)` as a filter, where the range form read the check index.
- **M7d** passes on this run (1.24 s against 1.29 s); on the run before it was 2% slower than the old form, within run-to-run variation.

## After parallel query off and one package branch per `or` rule (2026-11-14)

Sam's third step (`9d58ee1`): the evaluator's candidate statement also runs with `SET LOCAL max_parallel_workers_per_gather = 0`, and under `or` every package `eq`/`in` condition compiles into one branch. Evaluator-shaped rows run with both settings; M4 keeps the server defaults.

| # | Measurement | Statement shape | Args | First run plan / exec (ms) | Warm plan / exec (ms) | Rows | Plan notes | Threshold | Result |
|---|---|---|---|---|---|---|---|---|---|
| M1a | linux:linux_kernel, and | realtime | 12 | 1.20 / 0.20 | 0.32 / 0.10 | 1 |  | warm <= 5 ms | pass |
| M1b | linux:linux_kernel or in_cisa_kev | realtime | 13 | 0.32 / 0.19 | 0.31 / 0.16 | 1 | hashed SubPlan | warm <= 5 ms | pass |
| M2a | linux:linux_kernel, and | batch 5,000 | 12 | 26.01 / 6.77 | 30.03 / 3.10 | 0 |  | warm <= 3000 ms | pass |
| M2b | linux:linux_kernel or in_cisa_kev | batch 5,000 | 13 | 37.27 / 1139.53 | 28.24 / 1122.00 | 0 | hashed SubPlan; seq scan: cve_cpe_matches | warm <= 3000 ms | pass |
| M2c | nodejs:node.js, and | batch 5,000 | 12 | 33.16 / 3.02 | 30.99 / 2.92 | 0 |  | warm <= 3000 ms | pass |
| M3a | nodejs:node.js and severity critical/high | dry-run | 39 | 0.88 / 6.50 | 0.63 / 2.80 | 146 |  | warm <= 5000 ms | pass |
| M3b | nodejs:node.js alone | dry-run | 38 | 0.56 / 2.98 | 0.64 / 2.84 | 249 |  | warm <= 5000 ms | pass |
| M3c | nodejs:node.js or in_cisa_kev | dry-run | 39 | 0.54 / 355.58 | 0.59 / 359.51 | 2026 | hashed SubPlan; seq scan: cves | warm <= 5000 ms | pass |
| M3d | linux:linux_kernel alone | dry-run | 17 | 0.40 / 334.17 | 0.40 / 252.23 | 5001 |  | warm <= 5000 ms | pass |
| M3e | linux:linux_kernel or in_cisa_kev | dry-run | 18 | 0.35 / 354.13 | 0.36 / 348.88 | 5001 | hashed SubPlan; seq scan: cves | warm <= 5000 ms | pass |
| M4 | linux:linux_kernel | saved search, page of 50 | 17 | 0.79 / 156.17 | 0.42 / 167.12 | 51 |  | warm <= 5000 ms | pass |
| M5a | limit rule, or | realtime | 15 | 4.64 / 0.14 | 4.53 / 0.14 | 1 |  | warm <= 5 ms | pass |
| M5b | limit rule, or | dry-run | 736 | 12.58 / 4321.03 | 12.65 / 4289.32 | 5001 | seq scan: cves | warm <= 5000 ms | pass |
| M5c | limit rule, or | batch 5,000 | 15 | 44.87 / 380.75 | 44.90 / 402.27 | 4564 |  | warm <= 3000 ms | pass |
| M5d | limit rule, and (information) | realtime | 701 | 182.88 / 3.92 | 178.07 / 3.78 | 0 |  | information only | - |
| M5e | limit rule, and (information) | dry-run | 834 | 210.48 / 1070.86 | 214.29 / 1062.11 | 0 |  | information only | - |
| M5f | limit rule, and (information) | batch 5,000 | 701 | 2212.55 / 21.47 | 2547.29 / 18.84 | 0 |  | information only | - |
| M6 | 50 products, or | dry-run | 734 | 19.64 / 1531.43 | 14.57 / 1382.58 | 5001 | SubPlan NOT hashed | warm <= 5000 ms | pass (not hashed; within threshold) |
| M7a | npm, package in 50 names | dry-run | 2 | 0.47 / 1206.94 | 0.47 / 1151.69 | 0 |  | warm <= 5000 ms | pass |
| M7b | Debian, package eq openssl | dry-run | 3 | 0.48 / 19.70 | 0.39 / 8.81 | 395 |  | warm <= 5000 ms | pass |
| M7c | package eq openssl, no ecosystem | dry-run | 2 | 0.33 / 37.43 | 0.30 / 23.62 | 2037 |  | first run <= 5000 ms | pass |
| M7d-old | package contains lodash, no ecosystem, per-row EXISTS (before) | dry-run | 1 | 0.24 / 3219.45 | 0.26 / 3253.23 | 135 | seq scan: cve_affected_packages | information only | - |
| M7d | package contains lodash, no ecosystem, set form | dry-run | 1 | 0.26 / 3232.65 | 0.26 / 3335.76 | 135 | seq scan: cve_affected_packages | not slower than M7d-old | FAIL (slower than M7d-old) |

M8 read-only estimate (kept ingest): 2502 pages of 1000 IDs, 200438 matches, 4m10s read time.

M7d compared fairly: the two forms interleaved, five runs each (`TestKeptIngestContainsInterleaved`), because single triples flipped between pass and fail by a few percent:

| Run | Before (per-row EXISTS) plan+exec ms | Set form plan+exec ms |
|---|---|---|
| 1 | 3332.2 | 3300.5 |
| 2 | 3345.0 | 3314.2 |
| 3 | 3283.0 | 3348.6 |
| 4 | 3353.6 | 3341.8 |
| 5 | 3336.5 | 3316.5 |
| mean | 3330.1 | 3324.3 |

The set form is not slower (mean 3,324 ms against 3,330 ms): **pass**. Both forms take about 3.3 s serially, against 1.2 s for each with parallel query; both are under the design's 4.7 s reference and the 5 s dry-run threshold.

M8 full activation (disposable copy): 12m5s wall clock, 200252 events, rule status active, threshold 7 min, FAIL.

### Reading

- **Every statement threshold passes**: M5a realtime 4.7 ms, M5b dry-run 4.3 s, M5c batch 0.45 s, M6 1.4 s, M7d equal to the old form. The read-only M8 estimate covers the whole corpus in 4 min 10 s (200,438 matches) with no shared-memory error.
- **M8 fails on wall clock: 12 min 5 s against 7 minutes.** The activation completed (rule `active`, 200,252 events), inside the 15 minutes after which `SweepZombieActivations` fails a job. About 4 minutes are reads; about 8 are the 200,252 `InsertAlertEvent` calls, one transaction each (about 2.4 ms per event). That cost follows the number of matching CVEs, not the rule's shape: `severity in [critical, high]` matches 182,637 of the kept ingest's CVEs (critical 46,442, high 136,195), so an activation of that ordinary rule spends about the same time on inserts.
- Single-product rows are close to the design's figures; one single-product batch (M2b, `linux:linux_kernel` or `in_cisa_kev`) takes 1.1 s with a sequential scan of `cve_cpe_matches`, within the 3 s threshold.

## Task 5.5: the batch candidate scan with the re-check arm (disposable copy, 2026-11-14)

The copy at migration 63, with `UPDATE cves SET date_match_inputs_changed = date_modified_canonical` (every CVE merged once since the deploy) and `VACUUM ANALYZE`. The statement is the evaluator's `UNION` of two keyset scans (`getCVEsModifiedSince`, page size 1,000), run read-only with `EXPLAIN (ANALYZE, BUFFERS)`.

| Window | Page | Eligible CVEs | Plan | Execution |
|---|---|---|---|---|
| Dense: `since` = newest modification minus one day | first | 1,703,192 | Merge Append of two `cves_pkey` walks, date as filter | 561 ms |
| Dense | after the 3,000th eligible ID | 1,703,192 | same | 0.8 ms |
| Sparse: `since` = 99th percentile of modification times | first | 26,197 | same; the eligible rows sit at the end of `cve_id` order, so each walk reads most of the index (1.27 s for the `date_modified_canonical` arm, 2.43 s for the new arm) | **3,699 ms** |
| Sparse | from the `CVE-` range | 26,197 | bitmap scans of `cves_date_modified_canonical_idx` and `cves_date_match_inputs_changed_idx`, then sort | 127 ms |

Threshold: 3 s per page. **The sparse first page fails (3.7 s).** The planner walks the primary key when it expects more eligible rows than a page, which goes wrong when they are clustered at the end of the ID order; the existing arm alone took 1.27 s on the same page. A window of fewer eligible CVEs than a page uses the index-and-sort plan. Planning time is under 0.4 ms in every case. Sam accepted the sparse first page on 2026-11-14.

## M8 after batched activation inserts (2026-11-14)

This branch merged `origin/dev` with PR 243 (each activation page's events written in one transaction). The same limit rule under `or`, the same disposable copy (now at migration 63):

M8 full activation (disposable copy): 2 min 4 s wall clock, 200,252 events, rule status `active`, threshold 7 minutes: **pass** (12 min 5 s with one transaction per event).

## Set conditions in "and" rules (read-only, 2026-11-14)

Raised by the security review: under `and` each set condition stays its own `IN`, and realtime evaluates every organisation's active rules on each changed CVE. `TestKeptIngestAndSetSweep`: K of the largest products and K of the most common packages under `and`, with the evaluator's settings (JIT and parallel query off). These rules match nothing; the cost is planning.

| # | Measurement | Statement shape | Args | First run plan / exec (ms) | Warm plan / exec (ms) | Rows | Plan notes | Threshold | Result |
|---|---|---|---|---|---|---|---|---|---|
| A2-re | 1 products + 1 packages, and (2 sets) | realtime | 15 | 7.72 / 1.12 | 0.61 / 0.14 | 0 |  | warm <= 5 ms | pass; first run over threshold |
| A2-ba | 1 products + 1 packages, and (2 sets) | batch 5,000 | 15 | 45.41 / 19.93 | 66.58 / 4.37 | 0 |  | warm <= 3000 ms | pass |
| A4-re | 2 products + 2 packages, and (4 sets) | realtime | 29 | 1.86 / 1.07 | 1.60 / 0.27 | 0 |  | warm <= 5 ms | pass |
| A4-ba | 2 products + 2 packages, and (4 sets) | batch 5,000 | 29 | 90.81 / 3.03 | 92.57 / 4.12 | 0 |  | warm <= 3000 ms | pass |
| A6-re | 3 products + 3 packages, and (6 sets) | realtime | 43 | 1.96 / 0.28 | 2.03 / 0.29 | 0 |  | warm <= 5 ms | pass |
| A6-ba | 3 products + 3 packages, and (6 sets) | batch 5,000 | 43 | 138.68 / 2.92 | 138.30 / 2.95 | 0 |  | warm <= 3000 ms | pass |
| A10-re | 5 products + 5 packages, and (10 sets) | realtime | 71 | 3.89 / 0.37 | 3.93 / 0.34 | 0 |  | warm <= 5 ms | pass |
| A10-ba | 5 products + 5 packages, and (10 sets) | batch 5,000 | 71 | 235.21 / 49.47 | 219.16 / 13.30 | 0 |  | warm <= 3000 ms | pass |
| A20-re | 10 products + 10 packages, and (20 sets) | realtime | 141 | 10.57 / 0.65 | 15.15 / 0.76 | 0 |  | warm <= 5 ms | FAIL |
| A20-ba | 10 products + 10 packages, and (20 sets) | batch 5,000 | 141 | 442.22 / 14.37 | 435.16 / 17.15 | 0 |  | warm <= 3000 ms | pass |
| A50-re | 25 products + 25 packages, and (50 sets) | realtime | 351 | 58.05 / 2.07 | 72.29 / 2.20 | 0 |  | warm <= 5 ms | FAIL |
| A50-ba | 25 products + 25 packages, and (50 sets) | batch 5,000 | 351 | 1246.36 / 16.19 | 1129.95 / 15.65 | 0 |  | warm <= 3000 ms | pass |

Decision (2026-11-14): an `and` rule may hold at most 10 set conditions, the largest size that passed the 5 ms realtime threshold here (4.3 ms).
