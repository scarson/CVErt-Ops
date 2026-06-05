"""Request orchestration — establishes the call topology for the service.

This wires the existing modules into two request paths so the Execution Cost Map
(Lane 6) has a real structure to reason about. It introduces NO new performance
defects; it only makes the call topology explicit:

  handle_listing_request  (per page view)
    -> pricing.list_prices         -> get_landed_cost -> _compute_landed_cost (heavy: 50k-iter loop)
    -> inventory.find_duplicate_skus  (O(n^2) over request-sized skus)
    -> report.render_csv           (per-row string build)

  handle_checkout_request (per checkout)
    -> inventory.enrich_line_items (N+1 round-trips through repo.get)
    -> report.total_revenue        (per-row)

  config.load_enabled_flags is called ONCE at startup (cold path).
"""

import config
import inventory
import pricing
import report


def handle_listing_request(raw_products):
    """Hot path: render the product-listing page. raw_products is request-sized
    (tens to a few hundred), each a dict with id, name, price, base, shipping, sku."""
    priced = pricing.list_prices(raw_products)                      # fan-out × heavy unit cost
    dupes = inventory.find_duplicate_skus([p["sku"] for p in priced])  # O(n^2)
    csv = report.render_csv(raw_products)                           # per-row string growth
    return {"priced": priced, "dupes": dupes, "csv": csv}


def handle_checkout_request(order_item_ids):
    """Hot path: finalize an order."""
    enriched = inventory.enrich_line_items(order_item_ids)          # N+1 I/O round-trips
    rows = [{"qty": 1, "price": e["price"]} for e in enriched]
    return {"items": enriched, "revenue": report.total_revenue(rows)}


# Startup wiring — runs once when the process boots (cold path).
ENABLED_FLAGS = config.load_enabled_flags({"fast_export": True})
