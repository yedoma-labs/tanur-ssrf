# @yedoma-labs/tanur-ssrf

<picture>
  <source media="(max-width: 640px)" srcset="https://raw.githubusercontent.com/yedoma-labs/assets/main/resized/banner-resized-mobile.png">
  <img src="https://raw.githubusercontent.com/yedoma-labs/assets/main/resized/banner-resized.png" alt="Project Header">
</picture>

[![CI](https://github.com/yedoma-labs/tanur-ssrf/actions/workflows/ci.yml/badge.svg)](https://github.com/yedoma-labs/tanur-ssrf/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@yedoma-labs/tanur-ssrf.svg)](https://www.npmjs.com/package/@yedoma-labs/tanur-ssrf)
[![TypeScript](https://img.shields.io/badge/TypeScript-7-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **tanur** (*tanur*) — Yakutian (Sakha) for "(noch zu bestätigen)"

SSRF-safe `fetch` for Node.js: pins the DNS result, validates every resolved IP and every redirect hop. Zero dependencies.

Use it when your server fetches a URL that a user controls: webhooks, image URLs, link previews, import-by-URL.

```
pnpm add @yedoma-labs/tanur-ssrf
```

Supports ESM (`import`) and CommonJS (`require`). Requires Node.js 20+.

---

## The problem

Blocklists and hostname regexes do not stop server-side request forgery (SSRF):

- **DNS rebinding.** A hostname resolves to a public IP for the check and to `127.0.0.1` or `10.x` for the connection.
- **Redirect chains.** A public URL redirects to `http://localhost:6379` or `http://169.254.169.254/` (cloud metadata).
- **IP encodings.** `0x7f000001`, `2130706433`, `0177.0.0.1`, `[::ffff:127.0.0.1]`, `[::ffff:a9fe:a9fe]`, and NAT64 or 6to4 forms.
- **Hostname tricks.** Trailing dots, mixed case, `*.localhost`, `*.internal`.

`createSafeFetch` closes these gaps by design. It resolves a hostname once, checks every returned address, connects to exactly that address, and validates each redirect hop from scratch.

## Quick start

```ts
import { createSafeFetch, readBodyWithLimit, SafeFetchError } from "@yedoma-labs/tanur-ssrf";

const safeFetch = createSafeFetch({
	maxBytes: 5 * 1024 * 1024,
	timeoutMs: 5_000,
	maxRedirects: 3,
});

try {
	const response = await safeFetch(userSuppliedUrl);
	const body = await readBodyWithLimit(response, 1024 * 1024);
	// use body
} catch (error) {
	if (error instanceof SafeFetchError) {
		console.warn("blocked or failed:", error.code);
	}
	throw error;
}
```

`safeFetch` has the signature `(input: string | URL | Request, init?: RequestInit) => Promise<Response>`. The result is a standard `Response`.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `allowedProtocols` | `["https:", "http:"]` | Accepted URL protocols. Only `http:` and `https:` are dispatched. |
| `allowedPorts` | `[80, 443]` | Ports that may be contacted. Anything else fails with `PORT_NOT_ALLOWED`. |
| `allowPrivateNetworks` | `false` | Allow private, loopback, link-local and other reserved addresses. See the warning below. |
| `blockedHostnames` | `localhost`, `metadata.google.internal`, `.localhost`, `.internal` | Rejected before DNS. Entries starting with `.` match the suffix and the bare name. **Replaces** the default list, so keep the defaults if you pass your own. |
| `maxRedirects` | `5` | Redirects followed before `REDIRECT_LIMIT`. |
| `timeoutMs` | `10000` | Deadline for the whole call: DNS, connect, headers and body consumption. |
| `maxBytes` | none | Limit on decoded body bytes. Enforced while the body is read. |
| `resolver` | `dns.lookup(name, { all: true })` | Injectable `(hostname) => Promise<{ address }[]>`. Useful for tests and custom DNS policy. |

Invalid options throw `TypeError` when `createSafeFetch` is called.

## Errors

Every policy failure throws `SafeFetchError` with a `code`:

| Code | When |
| --- | --- |
| `PROTOCOL_NOT_ALLOWED` | Protocol is not in `allowedProtocols`, or is not `http:`/`https:` (for example `file:`, `ftp:`). |
| `PORT_NOT_ALLOWED` | Port is not in `allowedPorts`. |
| `INVALID_URL` | Unparsable URL, relative URL without base, or credentials in the URL (`user:pass@`). |
| `BLOCKED_HOSTNAME` | Hostname is on the blocklist. Checked before DNS. |
| `BLOCKED_ADDRESS` | Any resolved (or literal) address is in a blocked range, or a resolver returned a non-IP value. |
| `DNS_FAILURE` | The resolver failed or returned no addresses. |
| `REDIRECT_LIMIT` | More than `maxRedirects` redirects. |
| `REDIRECT_WITHOUT_LOCATION` | A 3xx redirect status without `Location`. |
| `TIMEOUT` | `timeoutMs` elapsed. |
| `BODY_TOO_LARGE` | Body exceeded `maxBytes`, or `readBodyWithLimit` hit its limit. |
| `NETWORK_ERROR` | Connection or protocol failure, or an unsupported `Content-Encoding`. |

Error messages never contain the URL, its query string or credentials. They name the blocked host or address only.

Caller-provided `AbortSignal` aborts are not converted. The original `AbortError` is thrown.

## Guarantees

- **One resolution per hop, and only that answer is used.** The hostname is resolved once. Every returned address is checked. If any one is blocked, the hop is rejected. The socket is opened to the validated address through a pinned `lookup`, so Node never resolves the name again. This prevents DNS rebinding between check and connect.
- **Host and TLS stay correct.** The `Host` header is the requested hostname (and port if not default). TLS SNI and certificate verification use the hostname, never the IP.
- **Every redirect is validated.** `Location` is resolved against the current URL. Protocol, credentials, port, hostname, DNS and IP checks run again for each hop. Redirects are never followed automatically.
- **Credentials are not forwarded across origins.** On a cross-origin redirect, `Authorization`, `Cookie` and `Proxy-Authorization` are dropped, as `fetch` does.
- **No socket reuse.** Each request uses a fresh connection, so a connection validated under one policy cannot serve another.
- **IP classification covers:** IPv4 `0/8`, `10/8`, `100.64/10`, `127/8`, `169.254/16`, `172.16/12`, `192.0.0/24`, `192.168/16`, `198.18/15`, `224/4`, `240/4`, `255.255.255.255`, and documentation ranges. IPv6 `::`, `::1`, `fc00::/7`, `fe80::/10`, `ff00::/8`, plus IPv4-mapped, IPv4-translated, NAT64, 6to4 and Teredo forms, each judged by the embedded IPv4 address where applicable. The NAT64 local-use prefix `64:ff9b:1::/48` (RFC 8215) and the documentation prefix `3fff::/20` (RFC 9637) are blocked as well.
- **Parser normalization.** Hostnames are lowercased, a single trailing dot is removed, and IPv6 brackets are handled. Non-canonical IPv4 forms are normalized by the WHATWG URL parser before the check.
- **Zero runtime dependencies.** Only `node:*` built-ins are used.

## Limits and what this does not protect against

- **OS and network level.** This library is not a sandbox. Attacks that exploit the operating system, a kernel or a network stack are out of scope. Egress filtering at the network layer (firewall, separate network namespace) is still recommended for high-risk workloads.
- **Proxies are not supported.** The pinned `lookup` connects directly. Environment proxy settings (`HTTP_PROXY`, `HTTPS_PROXY`) are not honored, and a configured proxy would receive the request without this policy applied at the proxy hop.
- **Time-of-check versus time-of-use.** The validated address is bound to the connection. Nothing else is pinned: an attacker-controlled server on an allowed public address can still send any content, so the body still needs `maxBytes` and content validation.
- **Hostname policy is a list.** `blockedHostnames` is advisory on top of the IP checks. Replacing the default list removes the hostname layer.
- **Lists age.** Reserved ranges are hard-coded. Review them when IANA changes allocations.
- **Node.js only.** Browsers and Deno or Bun runtimes are not supported and not tested.
- **Response-level compatibility.** Gzip, deflate and Brotli bodies are decoded. Other `Content-Encoding` values fail with `NETWORK_ERROR`. `redirect` in `init` is ignored, because redirects are always handled by this library.

### Do not use `allowPrivateNetworks` for untrusted input

`allowPrivateNetworks: true` disables the private, loopback, link-local and reserved address checks. Any URL can then reach internal services, including cloud metadata endpoints. Use it only in tests, or for destinations you know and trust. Keep the default `false` for anything derived from user input.

## Development

```sh
pnpm install
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

The test suite does not perform network requests. Integration tests use a loopback server and an injected resolver. The redirect tests stub `node:http` so that no socket is opened to the redirect targets.

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

MIT. See [LICENSE](LICENSE).
