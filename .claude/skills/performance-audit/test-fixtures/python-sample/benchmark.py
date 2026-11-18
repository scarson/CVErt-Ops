"""Representative workload driver — a REAL, runnable benchmark for the dynamic
profiling lane (Lane 8).

This is the "existing benchmark / representative workload" that lets Lane 8
activate honestly: it drives the two request paths in app.py at representative
sizes under cProfile, so the lane can report MEASURED hotspots instead of
guessing.

Run:  python benchmark.py
"""

import cProfile
import io
import pstats
import random

import app

random.seed(0)  # deterministic workload


def make_products(n):
    return [
        {
            "id": i,
            "name": f"item-{i}",
            "price": random.randint(1, 100),
            "base": random.randint(1, 100),
            "shipping": 5,
            "sku": f"SKU-{i % (n // 2 or 1)}",  # ~half are duplicate SKUs
        }
        for i in range(n)
    ]


def workload():
    products = make_products(50)        # representative listing size
    for _ in range(20):                 # 20 listing requests
        app.handle_listing_request(products)
    for _ in range(20):                 # 20 checkout requests
        app.handle_checkout_request(list(range(1, 31)))


if __name__ == "__main__":
    pr = cProfile.Profile()
    pr.enable()
    workload()
    pr.disable()
    out = io.StringIO()
    pstats.Stats(pr, stream=out).sort_stats("tottime").print_stats(12)
    print(out.getvalue())
