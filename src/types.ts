/** One address returned by a resolver. Compatible with `dns.lookup(name, { all: true })`. */
export interface ResolvedAddress {
	readonly address: string;
	readonly family?: number;
}

/**
 * Resolves a hostname to all of its addresses. Called exactly once per
 * request hop; the connection is pinned to an address from that single answer.
 */
export type Resolver = (hostname: string) => Promise<readonly ResolvedAddress[]>;

export interface SafeFetchOptions {
	/** URL protocols that are accepted. Only http: and https: can actually be dispatched. */
	readonly allowedProtocols?: readonly string[];
	/**
	 * Allow connections to private, loopback, link-local and other reserved addresses.
	 * Intended for tests and for known internal targets only.
	 */
	readonly allowPrivateNetworks?: boolean;
	/** Ports that may be contacted. Default: [80, 443]. */
	readonly allowedPorts?: readonly number[];
	/**
	 * Hostnames that are rejected before DNS resolution. Entries starting with "."
	 * match the suffix (and the bare name). Replaces the default list, so keep the
	 * defaults if you pass your own. Default: localhost, metadata.google.internal,
	 * .localhost, .internal.
	 */
	readonly blockedHostnames?: readonly string[];
	/** Maximum number of redirects that are followed. Default: 5. */
	readonly maxRedirects?: number;
	/** Deadline in milliseconds for the whole call, including DNS and body consumption. Default: 10000. */
	readonly timeoutMs?: number;
	/** Maximum number of decoded response body bytes. No limit when omitted. */
	readonly maxBytes?: number;
	/** Hostname resolver. Default: node:dns/promises lookup with all: true. */
	readonly resolver?: Resolver;
}

export type SafeFetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export const DEFAULT_ALLOWED_PROTOCOLS: readonly string[] = ["https:", "http:"];
export const DEFAULT_ALLOWED_PORTS: readonly number[] = [80, 443];
export const DEFAULT_BLOCKED_HOSTNAMES: readonly string[] = [
	"localhost",
	"metadata.google.internal",
	".localhost",
	".internal",
];
export const DEFAULT_MAX_REDIRECTS = 5;
export const DEFAULT_TIMEOUT_MS = 10_000;
