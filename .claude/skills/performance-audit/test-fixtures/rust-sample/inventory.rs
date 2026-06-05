//! Core-lane (algorithmic / memory) issues + a beyond-the-pack issue + a decoy.

use std::collections::HashMap;

// PLANTED #5 (core memory): `name.clone()` allocates a fresh String when a borrow
// (`&str`) would do — `tag_of` only reads it. Pass `&str`.
pub fn label_for(name: String) -> String {
    let t = tag_of(name.clone());   // needless clone; tag_of could take &str
    format!("{t}:{name}")
}

fn tag_of(s: String) -> String {
    s.chars().take(3).collect()
}

// counts unique SKUs.
//
// BEYOND-THE-PACK (floor-not-ceiling): `contains_key` THEN `insert` hashes the key
// TWICE per new entry. The Entry API (`*counts.entry(sku).or_insert(0) += 1`) hashes
// once. NO Rust-pack bullet names the contains_key-then-insert double-hash — the
// agent must know/reason about the Entry API. Bonus if found.
pub fn count_skus(skus: &[String]) -> HashMap<String, u32> {
    let mut counts: HashMap<String, u32> = HashMap::new();
    for sku in skus {
        if !counts.contains_key(sku) {     // hash #1
            counts.insert(sku.clone(), 0);  // hash #2 (+ a clone)
        }
        *counts.get_mut(sku).unwrap() += 1; // hash #3
    }
    counts
}

// DECOY: a `.clone()` of the (small, fixed) default settings, run ONCE at process
// startup. It mirrors the "needless clone" pattern from #5, BUT it is on a cold,
// run-once path over a tiny value — zero aggregate impact. Flagging "avoid the
// clone" here is a precision/checklist failure (calibration: cold-path micro-nit).
pub fn boot_defaults(base: &Settings) -> Settings {
    base.clone()
}

#[derive(Clone)]
pub struct Settings {
    pub region: String,
    pub retries: u8,
}
