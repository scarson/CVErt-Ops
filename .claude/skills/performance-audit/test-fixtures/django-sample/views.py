"""Representative Django ORM patterns (illustrative — NOT executed; no Django install needed).

This fixture exercises Lane 5 (framework-idiom currency): the planted issues are
correct code that a newer framework version supersedes — identifiable as problems
ONLY by consulting the currency brief (see currency-brief.md), not by generic
algorithmic/IO reasoning.

Assume `Order` and `User` are standard Django models with a default manager.
"""


def has_recent_orders(user_id):
    """Does the user have any recent orders?

    PLANTED LANE 5 ISSUE #1 (superseded idiom): uses `len(queryset)` to test
    existence, which executes the query AND instantiates every matching row just
    to check for >0. The currency brief flags `.exists()` as the fast path. The
    code is *correct* — only the idiom is stale.
    """
    qs = Order.objects.filter(user_id=user_id, status="recent")
    return len(qs) > 0


def order_net_amounts(user_id):
    """Net amount (amount - discount) per order.

    PLANTED LANE 5 ISSUE #2 (deprecated API): uses `QuerySet.extra()` with a raw
    SQL fragment. The brief flags `.extra()` as deprecated in favor of
    `annotate()` with ORM expressions. Works today; deprecated path.
    """
    return Order.objects.filter(user_id=user_id).extra(select={"net": "amount - discount"})


def mark_all_shipped(order_ids):
    """Mark a batch of orders shipped.

    PLANTED LANE 5 ISSUE #3 (new fast-path not used): saves each object in a loop.
    The brief notes `QuerySet.bulk_update()` as the framework fast path for exactly
    this. (Overlaps Lane 3, but the *currency* angle is "the framework now offers
    bulk_update for this pattern".)
    """
    orders = Order.objects.filter(id__in=order_ids)
    for o in orders:
        o.status = "shipped"
        o.save()


def active_admin_emails():
    """Normalized admin emails.

    DECOY (the brief does NOT cover this): a plain comprehension over a tiny fixed
    in-process list — no ORM, nothing version-specific. Lane 5 must NOT invent a
    currency issue here; nothing in the brief applies. Flagging it is a precision
    failure.
    """
    config_admins = ["Admin@Example.com", "Ops@Example.com"]
    return [e.lower() for e in config_admins]
