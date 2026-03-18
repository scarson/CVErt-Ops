# Cross-Reference: implementation-pitfalls.md vs testing-pitfalls.md

**Date:** 2026-03-18
**Analyst:** xref-testing agent (Explore)
**Scope:** Full comparison of both documents for overlaps, gaps, and cross-reference opportunities

---

## Summary Counts

| Category | Count |
|---|---|
| Direct overlaps (same pattern in both docs) | 7 |
| Testing insights → implementation implications | 7 |
| Implementation pitfalls → missing testing guidance | 16 |
| Recommended cross-references | 50+ |

**Key insight:** The documents are **complementary, not redundant**. Implementation-pitfalls is the design specification (what and why); testing-pitfalls is the verification checklist (how to prove it works). Cross-references should make this relationship explicit.

---

## Section 1: Overlapping Content

### Concurrency & TOCTOU
- **Testing-pitfalls §1** (multi-step flows, token consumption, rate limits, bootstrap races)
- **Implementation-pitfalls §2.8** (EPSS/CVE upsert race), **§5.16** (multi-tab refresh race)
- **Consistency:** PARTIALLY OVERLAPPING
- **Notes:** Testing focuses on detection strategies (barriers, concurrent triggers); implementation documents fixes (advisory locks, grace periods). Testing should reference §2.8 and §5.16 for code review patterns.

### Feed Data Quality
- **Testing-pitfalls §9** (null bytes, falsy values, sparse fields, wire format, timestamps, cursors)
- **Implementation-pitfalls §1.1-1.10** (JSON wire format, ZIP streaming, timestamp parser, polymorphic fields, defer in loop, URL encoding, ZIP pre-filter), **§2.10** (null byte poisoning), **§5.2-5.4** (bulk import, NVD windows)
- **Consistency:** PARTIALLY OVERLAPPING — testing is derivative of implementation design decisions
- **Notes:** Implementation specifies HOW to build adapters; testing specifies WHAT scenarios to cover. Cross-references should be explicit.

### RLS & Tenant Isolation
- **Testing-pitfalls §10** (dual-connection testing, cross-tenant, child table isolation, worker vs API tx)
- **Implementation-pitfalls §2.4** (RLS fail-closed), **§2.9** (child table bypass), **§2.13** (squirrel bypass), **§2.14** (AppStore for tests), **§2.17** (transaction helper selection), **§3.12** (bypassTx from handler)
- **Consistency:** HIGHLY CONSISTENT — perfect complementarity with no contradictions

### Security Enforcement
- **Testing-pitfalls §11** (RBAC matrix, JWT confusion, anti-enumeration, webhook SSRF, constant-time)
- **Implementation-pitfalls §3.1-3.12** (JWT, argon2, OAuth, API keys, SSRF, timing oracle)
- **Consistency:** HIGHLY CONSISTENT — implementation fixes + test verification are complementary

### Error Path Differentiation
- **Testing-pitfalls §3** (silent swallowing, information leakage, partial failure, error propagation)
- **Implementation-pitfalls §4.4-4.5** (activation scan, dry-run), **§13.1** (RLS deployment bypass)
- **Consistency:** PARTIALLY OVERLAPPING

### HTTP Server Timeouts & DOS Prevention
- **Testing-pitfalls §8** (failure reporting, production client configuration)
- **Implementation-pitfalls §3.7-3.8** (request body, Slowloris), **§4.9-4.10** (tarpitting, pool starvation), **§4.13** (ephemeral ports)
- **Consistency:** PARTIALLY OVERLAPPING

### Database Transactions
- **Testing-pitfalls §7** (transaction helper compliance, PATCH atomicity, audit trail, commit persistence)
- **Implementation-pitfalls §2.17** (transaction helper selection), **§2.4** (RLS fail-closed), **§2.13** (squirrel bypass)
- **Consistency:** HIGHLY CONSISTENT — §2.17 is the design spec, §7 is the verification pattern

---

## Section 2: Testing Insights → Implementation Implications

### TI-1. Bounded Growth Verification (testing §2 → implementation §5.14)
Implementation §5.14 documents rate limiter eviction. Testing §2 is broader — applies to lockout maps, caches, any sync.Map keyed by external input. Implementation doc should reference testing §2 for verification patterns.

### TI-2. Behavioral Parity Between Parse Paths (testing §9 → implementation feeds)
Generic adapter supports multiple parsing paths. Testing §9 says both must produce identical output. Implementation should note: feed adapters with multiple parse paths MUST test behavioral parity.

### TI-3. Audit Trail Completeness (testing §7 → implementation §13.2)
Testing §7: "verify ALL operations in same category have audit logging." Implementation §13.2 found defined event constants never emitted. Implementation should note: defined constants MUST have tests verifying emission.

### TI-4. Zero-Value Preservation (testing §4 → implementation §1.11)
Testing §4 specifies how to verify PATCH pointer types work correctly. Should explicitly reference §1.11 as the mandatory implementation pattern.

### TI-5. Dangerous Config Combinations (testing §5 → implementation §13.5)
Testing §5: reject dangerous config combos at startup. Implementation §13.5 found defaults contradicting docs. Implementation should have a checklist: every security config needs a startup validation test.

### TI-6. Feature Flag Enforcement at All Entry Points (testing §13 → implementation NP-1/NP-4)
Testing §13: admin flags must be enforced at all entry points (login, refresh, scheduler, triggers). This pattern spans multiple implementation sections.

### TI-7. Config Holder Consumer Verification (testing §15 → implementation NP-6)
Testing §15: verify every consumer reads from the holder, not startup config. Change holder value, assert operations use new value.

---

## Section 3: Implementation Pitfalls → Missing Testing Guidance

16 implementation patterns lack explicit testing guidance in testing-pitfalls.md:

| # | Implementation Pitfall | Missing Testing Guidance |
|---|---|---|
| 1 | §1.1-1.2 Feed wire format + ZIP | How to test Token() navigation and ZIP temp-file bridging |
| 2 | §1.8 defer in loop FD leak | How to measure FD count per-iteration in tests |
| 3 | §1.9 URL parameter encoding | How to test +/%2B encoding with mocked NVD |
| 4 | §1.10 ZIP pre-filter | How to verify entry.Open() NOT called for unmodified entries |
| 5 | §2.1-2.2 IS DISTINCT FROM / FTS isolation | How to verify dead tuple prevention |
| 6 | §2.8 Advisory lock coordination | How to test TOCTOU race between EPSS and merge |
| 7 | §2.12 Dynamic IN 65k / ANY array | How to test with 70k+ list items |
| 8 | §3.2-3.3 Argon2 semaphore | How to test non-blocking rejection under concurrent load |
| 9 | §3.4 Refresh token theft detection | How to test grace period + global invalidation |
| 10 | §3.9 Webhook HMAC replay | How to test 5-minute timestamp rejection window |
| 11 | §4.1 Activation scan silent mode | How to verify alert_events written but NOT notification_deliveries |
| 12 | §4.4 Activation scan async + state machine | How to test draft→activating→active transitions |
| 13 | §4.5 Dry-run rollback | How to verify no alert_events persistence |
| 14 | §4.14 Fan-out error isolation | How to inject per-channel failures and verify independence |
| 15 | §5.13 OSV/GHSA alias resolution | How to test alias→CVE PK migration |
| 16 | §5.19 pgx SimpleProtocol | How to verify query mode in tests |

---

## Section 4: Recommended Cross-References

### From testing-pitfalls.md → implementation-pitfalls.md:

| Testing Section | Should Reference | Purpose |
|---|---|---|
| §1 Concurrency | impl §2.8, §5.16 | Advisory lock and grace period patterns |
| §2 Negative Property | impl §5.14 | Eviction requirements for in-memory structures |
| §7 Transaction & Store | impl §2.17 | Transaction helper selection spec |
| §9 Feed Data Quality | impl §1.1-1.10 | Adapter wire format patterns being tested |
| §10 RLS & Tenant | impl §2.4, §2.9, §2.13, §2.17 | RLS design decisions |
| §11 Security Enforcement | impl §3.1-3.12 | Security mechanism specs |
| §14 Notification & Delivery | impl §4.10, §4.14 | Delivery patterns being verified |

### From implementation-pitfalls.md → testing-pitfalls.md:

| Implementation Section | Should Reference | Purpose |
|---|---|---|
| §1.1-1.10 Feed Adapters | testing §9 | Test scenarios for adapter patterns |
| §2.4 RLS Fail-Closed | testing §10 | Dual-connection test strategy |
| §2.8 Advisory Lock Race | testing §1 | Concurrent test barriers |
| §3.x Security Fixes | testing §11 | Security enforcement test patterns |
| §4.1-4.14 Operational | testing §8, §14 | Worker lifecycle and delivery tests |

### Proposed Mapping Table (for both docs):

| Implementation Fix | Testing Verification |
|---|---|
| §3.1 JWT WithValidMethods | testing §11 JWT algorithm confusion |
| §3.2 Argon2 semaphore | testing §8 load testing |
| §3.4 JTI + grace period | testing §11 token type enforcement |
| §3.5 OAuth state | testing §11 CSRF prevention |
| §3.9 Webhook HMAC | testing §11 replay prevention |
| §3.10 Constant-time compare | testing §11 timing oracle |
| §2.17 Transaction helpers | testing §7, §10 |
| §4.10 DB pool starvation | testing §8 external I/O isolation |
| §4.14 Fan-out independence | testing §14 error isolation |

---

## Key Insights

1. **Complementary, not redundant.** Implementation-pitfalls specifies WHAT and WHY; testing-pitfalls specifies HOW TO VERIFY. Neither replaces the other.

2. **Testing is derivative of design decisions.** Most testing scenarios are direct consequences of design choices in implementation-pitfalls (e.g., transaction helpers → test via AppStore).

3. **Missing cross-references are a usability gap.** A developer reading testing §9 would benefit from pointers to implementation §1.1-1.10 that document the patterns being tested.

4. **Feed adapters have the largest gap.** 16 missing test guidance items, most about feed adapter patterns.

5. **Security fixes are well-paired.** §3 (implementation) maps cleanly to §11 (testing).

6. **Transaction helpers are the bridge.** §2.17 is the critical design decision that testing §7 and §10 rely on. Should be prominently cross-referenced.
