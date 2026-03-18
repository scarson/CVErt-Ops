# CVErt Ops — Implementation Pitfalls & Review Findings

> **Purpose:** Document implementation traps, design flaws, and corrected decisions that would cause production failures, security vulnerabilities, or data correctness bugs if shipped. This document is the primary code review reference for the CVErt Ops codebase.
>
> **Relationship to testing-pitfalls.md:** This document specifies *what* to implement and *why*. `dev/testing-pitfalls.md` specifies *how to verify* those implementations work correctly. They are complementary — cross-references are noted inline.
>
> **Last validated against codebase:** 2026-03-18 (10-agent parallel audit)

---

## How to Use This Document

This document serves three audiences. Start here, then go directly to the section you need.

**If you're implementing code:** Go to the domain section matching your work area. Each entry has a clear *Flaw → Why It Matters → Fix → Lesson* structure. Follow the Fix. The Lesson teaches the generalizable principle so you'll catch the next instance of this pattern.

**If you're reviewing code:** Go to your domain section's **Review Checklist** at the end. Each item is a pass/fail check derived from the pitfalls above it. If a checklist item fails, read the referenced pitfall for context.

**If you're maintaining this document:** See **Appendix C: Document Maintenance Guide** for the update process and completeness checklist. Every update MUST follow that checklist — partial updates are how this document drifts.

---

## Table of Contents

| § | Section | You're working on... | Entries | Checklist |
|---|---------|---------------------|---------|-----------|
| 1 | [Feed Adapters & Data Ingestion](#1-feed-adapters--data-ingestion) | Feed adapters, streaming, ZIP, cursors, aliases | FEED-1 – FEED-20 | §1.C |
| 2 | [Database & Query Patterns](#2-database--query-patterns) | Store methods, migrations, SQL, RLS, transaction helpers | DB-1 – DB-25 | §2.C |
| 3 | [Authentication & Security](#3-authentication--security) | Auth, OAuth, JWT, API keys, MFA, lockout, secrets | AUTH-1 – AUTH-25 | §3.C |
| 4 | [API Design & HTTP](#4-api-design--http) | HTTP handlers, middleware, pagination, validation | API-1 – API-11 | §4.C |
| 5 | [Notification & Alert Evaluation](#5-notification--alert-evaluation) | Alerts, delivery, webhooks, fan-out, debounce | NOTIFY-1 – NOTIFY-19 | §5.C |
| 6 | [Architecture & Operations](#6-architecture--operations) | Startup, config, deployment, scheduling, cross-cutting | ARCH-1 – ARCH-44 | §6.C |
| A | [Historical Changelog](#appendix-a-historical-changelog) | Provenance, validation dates, review process meta-observations | — | — |
| B | [Unified Summary Table](#appendix-b-unified-summary-table) | All pitfalls at a glance, with severity and status | — | — |
| C | [Document Maintenance Guide](#appendix-c-document-maintenance-guide) | How to update this document correctly | — | — |

---
