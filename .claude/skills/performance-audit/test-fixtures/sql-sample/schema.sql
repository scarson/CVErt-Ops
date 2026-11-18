-- SQL fixture for the performance-audit evals (PostgreSQL dialect). The schema/DDL
-- is in scope so the auditor can reason about indexes and types. See
-- expected-findings.md (do NOT read it as the agent under test).

CREATE TABLE customers (
    id          bigserial PRIMARY KEY,
    email       varchar(255) NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_customers_email ON customers (email);

CREATE TABLE orders (
    id           bigserial PRIMARY KEY,
    customer_id  bigint NOT NULL REFERENCES customers(id),
    status       varchar(20) NOT NULL,
    total_cents  bigint NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);
-- NOTE: there is NO index on orders.customer_id, and NONE on orders.created_at.
CREATE INDEX idx_orders_status ON orders (status);

CREATE TABLE order_items (
    id        bigserial PRIMARY KEY,
    order_id  bigint NOT NULL REFERENCES orders(id),
    sku       varchar(64) NOT NULL,
    qty       int NOT NULL
);
CREATE INDEX idx_order_items_order_id ON order_items (order_id);
