# whoami rate-limit test no longer depends on timing

## What was done

`TestWhoami_APIKeyCountsAgainstOrgRateLimit` failed once in a full-suite run: `call 11: status = 200, want 429`. The test made ten calls on the free tier (60 a minute, burst 10) and expected the eleventh to be refused. Under full-suite load the ten calls took more than a second, the bucket refilled one token, and the eleventh call passed. The code was right; the test relied on ten requests finishing within a second.

The test now gives the org a 6-a-minute override: a burst of 1, with the next token after ten seconds. The first call succeeds and the second, sent at once, is refused, however slowly the machine runs.

## Quality checks

- `go test ./internal/api/ -run TestWhoami` and the whole `./internal/api/` package: pass.
