"""Structured warning builder for url-to-markdown.

Warnings emitted by the skill carry a stable machine-readable shape:
`{code, severity, recovery_action, ...extras}`. The `code` field is
constrained to KNOWN_CODES below; `recovery_action` to KNOWN_RECOVERY_ACTIONS;
`severity` to KNOWN_SEVERITIES. Agents branch on these structurally
instead of substring-matching the legacy human-readable warning list.

The module deliberately has no third-party dependencies. It is imported
at the top of url_to_markdown.py and lives on the same lib/ sys.path
entry as ssrf_guard.

Adding a new warning code:
  1. Add it to KNOWN_CODES below.
  2. Add a row to the structured warning catalog table in
     references/failure-modes.md.
  3. If a Phase 2-era diagnostic string still maps to it, update the
     warning-to-message translator in url_to_markdown.py.
"""

from __future__ import annotations

from typing import Any, Literal


# All codes the skill is allowed to emit. Adding a code requires updating
# this set AND the catalog table in references/failure-modes.md.
KNOWN_CODES = frozenset({
    # Phase 2 wires the first three into detect_quality_warnings_on_body();
    # these replace the legacy free-text diagnostics emitted in v1.0.
    "short_body_suspected_spa_or_paywall",
    "paywall_phrase_detected",
    "no_title_extracted",
    # v1.1 RESERVATION (intentionally unused): no call site in v1.1
    # emits this code. The hard-error path in extract_generic_trafilatura
    # raises ExtractError -> exit code 3 instead. The code is reserved
    # AND a translation branch exists in format_structured_warning_as_string
    # so that a FUTURE plan can convert that hard-fail to a soft-fail
    # (structured warning + complete:false + exit 0/8) without churning
    # KNOWN_CODES or breaking agents that already consume it. DO NOT
    # delete this code as "dead" -- its absence is what's reserved.
    "extraction_returned_no_content",
})

KNOWN_RECOVERY_ACTIONS = frozenset({"retry", "escalate", "accept"})

KNOWN_SEVERITIES = frozenset({"info", "warning"})


class WarningSchemaError(ValueError):
    """Raised when a warning emission violates the structured-warning schema."""


def warning(
    code: str,
    *,
    recovery_action: Literal["retry", "escalate", "accept"],
    severity: Literal["info", "warning"] = "warning",
    **extras: Any,
) -> dict[str, Any]:
    """Build a structured warning dict for inclusion in `extraction_warnings`.

    `code` MUST be in KNOWN_CODES (see module docstring on adding codes).
    `recovery_action` is one of {retry, escalate, accept}; agents branch
    on this to decide whether to surface, retry, or ignore the warning.
    `severity` is {info, warning}; in v1.1, EVERY structured warning
    (regardless of severity) is translated to a legacy string by
    url_to_markdown.format_structured_warning_as_string and appears in
    the legacy `warnings: [str]` envelope field for backwards compat.
    The `severity` field is the new authoritative signal for agents
    branching structurally; the legacy list stays exhaustive for agents
    reading prose.

    Extras are passed through verbatim -- typical fields include
    `recovery_hint`, `body_bytes`, `html_bytes`, `primary_attempted`,
    `primary_outcome`.
    """
    if code not in KNOWN_CODES:
        raise WarningSchemaError(
            f"unknown warning code {code!r}; known codes: {sorted(KNOWN_CODES)}"
        )
    if recovery_action not in KNOWN_RECOVERY_ACTIONS:
        raise WarningSchemaError(
            f"unknown recovery_action {recovery_action!r}; "
            f"known: {sorted(KNOWN_RECOVERY_ACTIONS)}"
        )
    if severity not in KNOWN_SEVERITIES:
        raise WarningSchemaError(
            f"unknown severity {severity!r}; known: {sorted(KNOWN_SEVERITIES)}"
        )
    return {
        "code": code,
        "severity": severity,
        "recovery_action": recovery_action,
        **extras,
    }
