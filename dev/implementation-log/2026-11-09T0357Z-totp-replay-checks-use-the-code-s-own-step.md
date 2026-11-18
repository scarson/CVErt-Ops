# TOTP replay checks use the code's own step

## What was built

- `matchingTOTPStep` in `internal/api/auth_mfa.go` returns the time step a submitted code belongs to, searching the steps the skew window accepts.
- `verifyTOTP` passes that step to `VerifyAndUpdateTOTPStep`, and takes the time as a parameter so tests can fix it.
- `CreateTOTPCredential` in `internal/store/mfa.go` creates the credential and records the confirming code's step in one transaction. `mfaTOTPConfirmHandler` uses it.

## Key decisions

- Reuse `totp.ValidateCustom` with `Skew: 0` once per candidate step. `pquerna/otp` returns only a bool for a window, and this keeps its length and format handling the same as before.
- Search from the latest step down. If one code value occurs in two steps of the window, recording the earlier step leaves the value acceptable at the later one.
- The store's compare-and-set did not change. It was correct; its input was wrong.
- Enrollment is in scope because a confirming code that is not recorded can pass the first login for up to 90 seconds.

## Gotchas

- `verifyTOTP` stored `currentStep + skew`. A code used at step S stored S+1. At step S+1 the same code was still valid and the compared value was S+2, so the check passed. The stored value and the compared value both moved with the clock.
- The same overshoot rejected legitimate codes: after a code from a client running behind was accepted, the next code was refused until the following step.
- `TestMFAVerifyTOTPReplay` showed this only when its two requests crossed a 30-second boundary. `TestTOTP_ReplayAcrossStepBoundaries` uses fixed times instead.
- `TestTOTP_ReplayPrevention_SkewWindow` asserted the stored value was `currentStep + skew`, so it encoded the defect. It now asserts the code's step.
- `TestFullTOTPLoginFlow` logged in with the code that confirmed enrollment. It now uses the next step's code.

## Known limits

- A `last_used_step` written before this change is at most one step ahead of the server's clock at that login. It can reject a new code only during the 30 to 60 seconds after that login, so no migration is needed.
- `verifyTOTP` returns a server error for a code of the wrong length, because `pquerna/otp` reports that as an error rather than a mismatch. This is unchanged here.

## Quality checks

- Before the fix, `TestTOTP_ReplayAcrossStepBoundaries` failed with `replay after the next boundary: verifyTOTP = true, want false`, and `next code: verifyTOTP = false, want true`.
- With only the verify path fixed, `TestTOTPConfirm_CodeCannotBeReplayedAtLogin` failed with `got 200, want 401`.
- Break-tested by searching steps from earliest to latest: `TestMatchingTOTPStep` failed on the real collision at steps 60202684 and 60202685 of the test secret.
- `go test ./internal/api/ ./internal/store/ -run "MFA|TOTP|Totp|Mfa" -count=1` passes with a real Postgres (`TESTCONTAINERS_RYUK_DISABLED=true`, because of the known reaper `removing` failure on this host).
- `golangci-lint run ./internal/api/... ./internal/store/...` reports 0 issues.
