import { lookup } from "node:dns/promises";
import { SafeFetchError } from "./errors.js";
import { getBlockedRange, parseIp } from "./ip.js";
import {
	DEFAULT_ALLOWED_PORTS,
	DEFAULT_ALLOWED_PROTOCOLS,
	DEFAULT_BLOCKED_HOSTNAMES,
	DEFAULT_MAX_REDIRECTS,
	DEFAULT_TIMEOUT_MS,
	type Resolver,
	type SafeFetchOptions,
} from "./types.js";

export interface ResolvedOptions {
	readonly allowedProtocols: readonly string[];
	readonly allowPrivateNetworks: boolean;
	readonly allowedPorts: readonly number[];
	readonly blockedHostnames: readonly string[];
	readonly maxRedirects: number;
	readonly timeoutMs: number;
	readonly maxBytes: number | undefined;
	readonly resolver: Resolver;
}

/** A validated connection target. `address` is the only IP the socket may connect to. */
export interface Target {
	readonly url: URL;
	readonly protocol: "http:" | "https:";
	/** Normalized hostname without brackets or trailing dot. Used for SNI and the Host header. */
	readonly hostname: string;
	readonly isIpLiteral: boolean;
	readonly port: number;
	readonly path: string;
	readonly address: string;
	readonly family: 4 | 6;
}

const DEFAULT_PORTS: Readonly<Record<"http:" | "https:", number>> = {
	"http:": 80,
	"https:": 443,
};

const PROTOCOL_PATTERN = /^[a-z][a-z0-9+.-]*:$/;

const defaultResolver: Resolver = (hostname) => lookup(hostname, { all: true, verbatim: true });

/** Validates caller options and applies defaults. Invalid options throw TypeError. */
export function resolveOptions(options: SafeFetchOptions): ResolvedOptions {
	const allowedProtocols = [...(options.allowedProtocols ?? DEFAULT_ALLOWED_PROTOCOLS)];
	for (const protocol of allowedProtocols) {
		if (!PROTOCOL_PATTERN.test(protocol)) {
			throw new TypeError(`Invalid protocol in allowedProtocols: ${protocol}`);
		}
	}

	const allowedPorts = [...(options.allowedPorts ?? DEFAULT_ALLOWED_PORTS)];
	for (const port of allowedPorts) {
		if (!Number.isInteger(port) || port < 1 || port > 65535) {
			throw new TypeError(`Invalid port in allowedPorts: ${String(port)}`);
		}
	}

	const blockedHostnames = (options.blockedHostnames ?? DEFAULT_BLOCKED_HOSTNAMES).map((entry) =>
		entry.toLowerCase().replace(/\.$/, ""),
	);

	const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
	if (!Number.isSafeInteger(maxRedirects) || maxRedirects < 0) {
		throw new TypeError("maxRedirects must be a non-negative integer");
	}

	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2_147_483_647) {
		throw new TypeError("timeoutMs must be a positive number of milliseconds");
	}

	const maxBytes = options.maxBytes;
	if (maxBytes !== undefined && (!Number.isSafeInteger(maxBytes) || maxBytes < 0)) {
		throw new TypeError("maxBytes must be a non-negative integer");
	}

	const resolver = options.resolver ?? defaultResolver;
	if (typeof resolver !== "function") {
		throw new TypeError("resolver must be a function");
	}

	return {
		allowedProtocols,
		allowPrivateNetworks: options.allowPrivateNetworks ?? false,
		allowedPorts,
		blockedHostnames,
		maxRedirects,
		timeoutMs,
		maxBytes,
		resolver,
	};
}

/** Parses a URL, with or without base. Never echoes the input in the error. */
export function parseUrl(input: string, base?: URL): URL {
	try {
		return new URL(input, base);
	} catch {
		throw new SafeFetchError("INVALID_URL", "Invalid URL");
	}
}

/**
 * Lowercases, strips IPv6 brackets and one trailing dot. Rejects names that
 * are empty after normalization.
 */
export function normalizeHostname(rawHostname: string): string {
	let hostname = rawHostname.toLowerCase();
	if (hostname.startsWith("[") && hostname.endsWith("]")) {
		hostname = hostname.slice(1, -1);
	}
	if (hostname.endsWith(".")) {
		hostname = hostname.slice(0, -1);
	}
	if (hostname === "" || hostname.endsWith(".")) {
		throw new SafeFetchError("INVALID_URL", "Invalid URL");
	}
	return hostname;
}

export function isBlockedHostname(hostname: string, blocked: readonly string[]): boolean {
	return blocked.some((entry) => {
		if (entry.startsWith(".")) {
			return hostname === entry.slice(1) || hostname.endsWith(entry);
		}
		return hostname === entry;
	});
}

function assertNoCredentials(url: URL): void {
	if (url.username !== "" || url.password !== "") {
		throw new SafeFetchError("INVALID_URL", "URLs with credentials are not allowed");
	}
}

function raceAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
	if (signal.aborted) {
		promise.catch(() => undefined);
		return Promise.reject(new DOMException("The operation was aborted", "AbortError"));
	}
	return new Promise<T>((resolve, reject) => {
		const onAbort = () => reject(new DOMException("The operation was aborted", "AbortError"));
		signal.addEventListener("abort", onAbort, { once: true });
		promise.then(
			(value) => {
				signal.removeEventListener("abort", onAbort);
				resolve(value);
			},
			(error: unknown) => {
				signal.removeEventListener("abort", onAbort);
				reject(error);
			},
		);
	});
}

async function resolveAddresses(
	options: ResolvedOptions,
	hostname: string,
	signal: AbortSignal,
): Promise<string[]> {
	let answers: readonly { readonly address?: unknown }[];
	try {
		answers = await raceAbort(options.resolver(hostname), signal);
	} catch (error) {
		if (signal.aborted) {
			throw error;
		}
		throw new SafeFetchError("DNS_FAILURE", `DNS lookup failed for ${hostname}`);
	}
	if (!Array.isArray(answers) || answers.length === 0) {
		throw new SafeFetchError("DNS_FAILURE", `DNS lookup returned no addresses for ${hostname}`);
	}
	return answers.map((answer) => {
		if (typeof answer?.address !== "string") {
			throw new SafeFetchError(
				"BLOCKED_ADDRESS",
				`Resolver returned a non-IP value for ${hostname}`,
			);
		}
		return answer.address;
	});
}

/**
 * Validates one URL hop and resolves it to exactly one pinned address.
 *
 * Every address returned for the hostname is checked. If any of them is blocked,
 * the whole hop is rejected, so a mixed answer cannot be used to smuggle a private
 * address past the check.
 */
export async function resolveTarget(
	url: URL,
	options: ResolvedOptions,
	signal: AbortSignal,
): Promise<Target> {
	assertNoCredentials(url);

	const protocol = url.protocol;
	if (
		(protocol !== "http:" && protocol !== "https:") ||
		!options.allowedProtocols.includes(protocol)
	) {
		throw new SafeFetchError("PROTOCOL_NOT_ALLOWED", `Protocol not allowed: ${protocol}`);
	}

	const port = url.port === "" ? DEFAULT_PORTS[protocol] : Number(url.port);
	if (!options.allowedPorts.includes(port)) {
		throw new SafeFetchError("PORT_NOT_ALLOWED", `Port not allowed: ${String(port)}`);
	}

	const hostname = normalizeHostname(url.hostname);
	const literal = parseIp(hostname);
	if (literal === undefined && isBlockedHostname(hostname, options.blockedHostnames)) {
		throw new SafeFetchError("BLOCKED_HOSTNAME", `Hostname not allowed: ${hostname}`);
	}

	const candidates =
		literal === undefined ? await resolveAddresses(options, hostname, signal) : [hostname];
	if (candidates.length === 0) {
		throw new SafeFetchError("DNS_FAILURE", `DNS lookup returned no addresses for ${hostname}`);
	}

	let pinned: { address: string; family: 4 | 6 } | undefined;
	for (const candidate of candidates) {
		const ip = parseIp(candidate);
		if (ip === undefined) {
			throw new SafeFetchError("BLOCKED_ADDRESS", `Not a valid IP address for ${hostname}`);
		}
		if (!options.allowPrivateNetworks) {
			const range = getBlockedRange(ip);
			if (range !== undefined) {
				throw new SafeFetchError(
					"BLOCKED_ADDRESS",
					`Address ${candidate} of ${hostname} is in a blocked range: ${range}`,
				);
			}
		}
		pinned ??= { address: candidate, family: ip.family };
	}
	if (pinned === undefined) {
		throw new SafeFetchError("DNS_FAILURE", `DNS lookup returned no addresses for ${hostname}`);
	}

	return {
		url,
		protocol,
		hostname,
		isIpLiteral: literal !== undefined,
		port,
		path: `${url.pathname}${url.search}`,
		address: pinned.address,
		family: pinned.family,
	};
}
