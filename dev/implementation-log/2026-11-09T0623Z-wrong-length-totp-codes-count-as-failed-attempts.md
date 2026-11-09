# Wrong-length TOTP codes count as failed attempts

## What was built

- `matchingTOTPStep` in `internal/api/auth_mfa.go` reports `otp.ErrValidateInputInvalidLength` as a mismatch. A wrong-length code now takes the wrong-code path in `mfaVerifyHandler` (401, lockout failure recorded, `EventMFAVerifyFailed`) and in `mfaTOTPConfirmHandler` (401, `EventMFAEnrollmentFailed`).

## Key decisions

- Match the one library error and not all of them. The length of a code comes from the submitter. An undecodable stored secret (`otp.ErrValidateSecretInvalidBase32`) is a server fault and stays a 500.
- Use the library's error instead of a length check before the call. `hotp.ValidateCustom` trims whitespace and then counts bytes; a separate check would have to repeat that.

## Gotchas

- `/auth/mfa/verify` accepts codes of 1 to 20 characters for every method, so a TOTP code of the wrong length passed the schema.
- `/auth/mfa/totp/confirm` was also affected despite `minLength:"6" maxLength:"6"`. The schema counts characters and the library counts bytes after trimming, so `"12345 "` and `"é23456"` passed the schema and failed the library's check.
- Email OTP and recovery codes are hashed before comparison, so any length is an ordinary mismatch.
- `"é2345"` is exactly 6 bytes and does not trigger the length error; the test input is `"é23456"`.

## Quality checks

- Before the fix, `TestMFAVerify_WrongLengthCodesCountTowardLockout` and `TestTOTPConfirmWrongLengthCode` failed with `got 500, want 401`, and `TestMatchingTOTPStep` failed with `Input length unexpected`.
- Break-tested by ignoring every library error: the `undecodable secret is an error` subtest of `TestMatchingTOTPStep` failed with `error = <nil>`.
- `go test ./internal/api/ -run "MFA|TOTP|Totp|Mfa" -count=1` passes (`TESTCONTAINERS_RYUK_DISABLED=true`, because of the known reaper `removing` failure on this host).
- `golangci-lint run ./internal/api/...` reports 0 issues.
- The `security-review` skill found no failures across the TOTP verify and enrollment code.
