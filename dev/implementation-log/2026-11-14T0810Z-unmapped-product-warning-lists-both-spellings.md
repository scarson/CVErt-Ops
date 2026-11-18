# The unmapped-product warning names every CNA spelling that matches

## What was built

| Feature | Files | Description |
|---|---|---|
| Design | `dev/plans/2026-11-13-product-match-rules-design.md` section 8 | The unmapped-product row now says a part with an unescaped `_` lists both of its own names, with `_` read as a space first, and that any vendor spelling pairs with any product spelling. |
| Message | `internal/alert/dsl/validator.go` (`msgUnmappedProduct`, `spellings`) | The warning lists each part's distinct spellings from `check.NamesFor`, joined by "or": `vendor "acme corp" or "acme_corp" and product "big&small widget" or "big&small_widget"`. It named only the first pair, the `_`-as-space reading, though the CPE's own spelling with `_` and the mixed pairs also match a CNA row (`check.ownNames` builds every vendor × product pair). |
| Tests | `internal/alert/dsl/dsl_test.go` (`TestValidate_ProductUnmappedWarning`) | Both parts with `_`, and only the product with `_`. |

## Key decisions

- The design changed first, as the MATCH-2 code review asked (product-match-rules plan, Discoveries).

## Gotchas discovered

- `check.ParseProductValue` drops an unneeded escape, so `big\_widget` is the same value as `big_widget` and gets both spellings.

## Quality checks

- `TestValidate_ProductUnmappedWarning` failed first on the new wording, then passed; `go test ./internal/alert/dsl/`: pass.
