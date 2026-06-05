"""Application config, loaded ONCE at startup.

Contains the DECOY (see expected-findings.md): a tiny cold-path inefficiency a
well-calibrated audit should NOT flag.
"""

# Fixed, tiny set of known feature flags — never grows with load.
_FLAGS = ["beta_ui", "fast_export", "new_pricing", "audit_log"]


def load_enabled_flags(env):
    """Build the enabled-flag lookup once, at process startup.

    DECOY (should NOT be flagged): this sorts a fixed 4-element list and uses a
    list membership check. It is O(n^2)-ish in theory, but n is a constant 4 and
    this runs exactly once at startup — zero aggregate impact. A calibrated audit
    treats this as NOT a finding (cold path, bounded tiny n). Flagging it is a
    precision failure.
    """
    enabled = []
    for flag in sorted(_FLAGS):
        if flag not in enabled and env.get(flag):
            enabled.append(flag)
    return enabled
