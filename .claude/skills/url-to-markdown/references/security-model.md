# Security model

This document describes the threat model this skill is designed against, the specific defenses it implements, and — importantly — the attack surface it does **not** cover. A skill that fetches arbitrary URLs is an SSRF risk if used carelessly, and naming the limits clearly is more useful than pretending the defenses are complete.

## Threat model

**Context:** This skill runs on a user's local machine as a CLI tool. It is invoked by either (a) a human typing a URL, or (b) an AI agent passing URLs discovered during a task. It is **not** a public-facing HTTP endpoint accepting attacker-submitted URLs, which is the classic SSRF scenario.

**What the skill treats as semi-trusted:**

- URLs passed via command line — the user or agent chose them
- The agent itself — assumed benign but potentially prompt-injectable

**What the skill treats as hostile:**

- The target server's response — could contain any content, could redirect
- DNS responses for the target — could be attacker-controlled if the target is a hostile domain
- Cloud metadata endpoints on the same network — always suspect

**Specific attacks in scope:**

1. **Accidental localhost / internal-network fetches.** An agent is prompt-injected to fetch `http://localhost:8080/admin` or `http://internal-wiki/secrets` and leaks the response back through the agent's context window.

2. **Cloud metadata credential theft.** On a cloud VM, fetching `http://169.254.169.254/latest/meta-data/iam/security-credentials/` returns IAM credentials. The skill must refuse this unconditionally.

3. **Redirect-based pivot.** A public URL redirects (301/302) to a private URL, and the second fetch lands on an internal service. Mitigation requires re-validation on every redirect hop, not just the initial URL.

4. **Scheme-based exfiltration.** A URL with scheme `file://`, `gopher://`, `dict://`, etc., could access local files or exploit protocol-specific weaknesses. Mitigation: allow only http/https.

**Specific attacks explicitly out of scope for v1:**

1. **DNS rebinding.** An attacker-controlled DNS server returns alternating public/private addresses, winning the TOCTTOU race between DNS validation and the HTTP fetch. Mitigation would require IP pinning via `CURLOPT_RESOLVE`, which curl_cffi 0.15.0's high-level Session API does not expose. See "Known limitations" below.

2. **Parser differentials.** The URL parser used for validation (Python stdlib `urllib.parse`) could disagree with the URL parser used by libcurl (inside curl_cffi) on exotic inputs, potentially allowing a URL to pass validation but fetch something else. Mitigation: use the same parser end-to-end, which we approximate by passing the literal user-supplied URL through without transformation.

3. **Adversarial TLS / downgrade.** A malicious server negotiating weak TLS to extract information. Mitigation: trust libcurl's defaults.

4. **Side-channel timing.** Response-time analysis to infer whether an internal endpoint exists even if the fetch is blocked. Not mitigated.

## Defenses implemented

All defenses live in `scripts/lib/ssrf_guard.py` and the fetch-loop in `scripts/url_to_markdown.py`.

### 1. Scheme whitelist

Only `http` and `https` schemes are allowed. Everything else raises `SSRFError` at validation time. This includes `file://`, `gopher://`, `dict://`, `ftp://`, `ssh://`, custom app schemes, and anything else libcurl could theoretically handle.

### 2. Cloud metadata block (unconditional)

The following targets are hard-blocked and **cannot be overridden** by `--allow-private`:

**IP addresses:**

- `169.254.169.254` — AWS IMDSv1 (and v2 via token), GCP, Azure, DigitalOcean, Oracle Cloud
- `fd00:ec2::254` — AWS IPv6 metadata
- `100.100.100.200` — Alibaba Cloud

**Hostnames:**

- `metadata.google.internal`
- `metadata.goog`
- `metadata.azure.com`

These IPs and hostnames have no legitimate use case for "transcribe an article." They are blocked before DNS resolution even happens for the hostname list.

### 3. Private IP soft-block

The following categories are refused **by default** but can be overridden with `--allow-private`:

- Loopback (127.0.0.0/8, ::1)
- RFC1918 private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Link-local (169.254.0.0/16 non-metadata, fe80::/10)
- Reserved / non-global (multicast, 0.0.0.0, etc.)

The override exists because local dev servers, internal corporate wikis, and home-lab setups are legitimate targets for article transcription — it would be wrong to hard-block them. The default refusal catches accidental internal-network fetches; the explicit opt-in flag makes the decision auditable.

### 4. Per-redirect revalidation

Every redirect hop (up to `--max-redirects`, default 5) re-runs the full SSRF policy check on the new URL before following it. A public-to-private redirect attack is caught at the hop boundary. The redirect handler is implemented manually in `fetch_with_revalidation()` with `allow_redirects=False` on the underlying HTTP call — curl_cffi's automatic redirect following is disabled so we can intercept each hop.

### 5. Redirect loop and depth limits

The fetcher tracks visited URLs and fails with a clear `FetchError` on cycles. The hop counter is a secondary backstop in case two URLs differ only in query parameters but functionally loop.

### 6. All resolved addresses validated

When `socket.getaddrinfo()` returns multiple addresses (dual-stack IPv4+IPv6, round-robin load-balancer entries), **every** returned address is validated against the policy. A "first address passes, second is private" attack is caught. Any single violation refuses the entire URL.

## Known limitations

### DNS rebinding is not defeated

curl_cffi 0.15.0's high-level `Session` / `requests` API does not expose `CURLOPT_RESOLVE`, which is the libcurl primitive that would let us pin a validated IP to the actual HTTP connection. Without it, there is a (small) TOCTTOU window between our DNS-validation lookup and libcurl's internal DNS lookup during the fetch. A server under attacker control with a rebinding DNS setup could, in principle, return a public IP to our validator and a private IP to libcurl's fetch.

**Why v1 ships without this defense:**

1. The attack requires adversary-controlled DNS infrastructure plus timing luck inside a race window measured in milliseconds.
2. In our threat model (agent fetching URLs on behalf of a user), if the agent has been compromised enough to pass an attacker-controlled domain to the skill, there are easier attack paths than DNS rebinding.
3. Fixing it properly requires bypassing curl_cffi's Session API and building low-level `Curl` instances with manual `setopt(CurlOpt.RESOLVE, ...)`, which adds ~50 lines of code and ongoing maintenance burden for a narrow defense.

**What to do instead if your threat model includes DNS rebinding:**

- Run the skill inside a sandboxed container with network egress policy
- Route traffic through an egress CONNECT proxy such as [Stripe's Smokescreen](https://github.com/stripe/smokescreen) that enforces allow/deny lists at the network layer
- Replace curl_cffi with a lower-level client that exposes `CURLOPT_RESOLVE` and extend `fetcher` to use it

### Application-layer SSRF libraries are not complete defenses

Per Include Security's 2023 SSRF retrospective ([mitigating-ssrf-in-2023](https://blog.includesecurity.com/2023/03/mitigating-ssrf-in-2023/)), application-layer mitigation alone is insufficient for server-side applications accepting hostile URLs from the public internet. Their recommended mitigation is a network-layer egress proxy (Smokescreen) combined with authentication on internal services.

This skill's threat model is narrower — a local CLI tool fetching URLs chosen by the user or a semi-trusted agent — which makes application-layer mitigation a reasonable primary defense. But for deployments in higher-risk contexts (multi-tenant systems, public-facing invocation, untrusted agents), **treat this skill's SSRF protection as a belt, not a parachute.** Add network-layer controls.

### Side-channel timing is unmitigated

A sufficiently motivated attacker can distinguish "URL refused by SSRF policy" from "URL refused by HTTP error" from "URL returned content" by observing the skill's response time. If that distinction matters for your threat model, the skill is not the right tool.

### Response size is not capped

The skill currently does not cap response body size. A malicious server could return an extremely large response to exhaust memory. Mitigation for future versions: pass `max_recv_speed` or equivalent to curl_cffi and/or truncate at a fixed byte count before extraction.

### Output path is not sandboxed

The `--out DIR` argument is resolved via `Path(args.out).expanduser().resolve()` with no restriction on where it points. An invocation with `--out /../../etc/` or `--out ~/.ssh/` will happily write into sensitive directories if the user has permission.

**Why this is not enforced:** legitimate use cases span the entire user home directory (a user saves articles to `~/Documents/articles`, `~/obsidian-vault/`, `~/project/docs/`, etc.). Any allowlist restrictive enough to be meaningful would also reject legitimate targets. Any blocklist (refuse `/etc/`, `/root/`, `%SystemRoot%`) would be OS-specific and easy to circumvent via symlink.

**When this matters:**

- An agent invoked with `--json` mode could, if prompt-injected, be directed to write files outside the user's intended location.
- A script passing untrusted user input as `--out` is a potential exfiltration vector.

**Mitigation:** if you invoke this skill from an agent harness, have the calling layer validate the output directory against the agent's allowed workspace before passing `--out` down. The skill cannot enforce this safely on its own without breaking legitimate interactive use.

## When to NOT use this skill

- **Server-side, public-facing invocation.** This skill is designed for local use. Exposing it as a web service (e.g., `/transcribe?url=...` endpoint) would re-introduce the classic SSRF threat model and require network-layer mitigations this skill does not provide.
- **Multi-user contexts without per-user isolation.** One user's `--allow-private` invocation shouldn't give another user access to the same network. Not a concern in single-user CLI mode.
- **Any context where the URL source is fully hostile.** For hostile-URL scenarios, run the skill inside a container or VM with restricted network egress.

## Upgrade path

If the threat model changes and you need DNS rebinding defense:

1. Switch `fetch_with_revalidation` in `scripts/url_to_markdown.py` from `ccr.get(...)` to a low-level `Curl` instance with `setopt(CurlOpt.RESOLVE, [f"{host}:{port}:{ip}"])` after DNS validation.
2. Handle `Curl.impersonate()` manually, since the high-level Session wrapper does this for you today.
3. Add a test fixture that exercises the rebinding path (can be faked with a test DNS server or cached `addrinfo` mock).

Track the issue against upstream curl_cffi — if a later version exposes `resolve=` on the high-level Session, the upgrade is trivial.
