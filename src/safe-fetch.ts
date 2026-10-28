import { SafeFetchError } from "./errors.js";
import { parseUrl, type ResolvedOptions, resolveOptions, resolveTarget } from "./policy.js";
import { type OutgoingRequest, sendRequest, toResponse } from "./transport.js";
import type { SafeFetch, SafeFetchOptions } from "./types.js";

const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);
/** Request headers that are never forwarded. Host is always set to the validated target. */
const DROPPED_REQUEST_HEADERS: ReadonlySet<string> = new Set([
	"host",
	"content-length",
	"transfer-encoding",
	"connection",
]);
/** Credentials are not sent to a different origin after a redirect, matching fetch. */
const CROSS_ORIGIN_HEADERS: readonly string[] = ["authorization", "cookie", "proxy-authorization"];

interface PreparedRequest {
	readonly url: URL;
	readonly method: string;
	readonly headers: Record<string, string>;
	readonly body: Uint8Array | undefined;
}

/**
 * Creates a fetch-compatible function that validates every URL, resolves each
 * hostname once, connects to the validated IP only, and validates every redirect.
 *
 * Throws SafeFetchError for policy violations. Throws TypeError for invalid options
 * or unsupported body types.
 */
export function createSafeFetch(options: SafeFetchOptions = {}): SafeFetch {
	const config = resolveOptions(options);
	return (input, init) => fetchSafely(config, input, init);
}

async function toBytes(body: BodyInit): Promise<Uint8Array> {
	if (typeof body === "string") {
		return new TextEncoder().encode(body);
	}
	if (body instanceof ArrayBuffer) {
		return new Uint8Array(body.slice(0));
	}
	if (ArrayBuffer.isView(body)) {
		return new Uint8Array(body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength));
	}
	if (body instanceof URLSearchParams) {
		return new TextEncoder().encode(body.toString());
	}
	if (body instanceof Blob) {
		return new Uint8Array(await body.arrayBuffer());
	}
	throw new TypeError(
		"Unsupported request body; use a string, ArrayBuffer, ArrayBufferView, URLSearchParams or Blob",
	);
}

async function prepareRequest(
	input: string | URL | Request,
	init: RequestInit | undefined,
): Promise<PreparedRequest> {
	const rawUrl = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
	const url = parseUrl(rawUrl);
	const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();

	const merged = new Headers(input instanceof Request ? input.headers : undefined);
	if (init?.headers !== undefined) {
		new Headers(init.headers).forEach((value, key) => merged.set(key, value));
	}
	const headers: Record<string, string> = {};
	merged.forEach((value, key) => {
		if (!DROPPED_REQUEST_HEADERS.has(key)) {
			headers[key] = value;
		}
	});
	// Compressed responses would otherwise reach the caller undecoded when the caller did not ask for them.
	headers["accept-encoding"] ??= "identity";

	let body: Uint8Array | undefined =
		init?.body === undefined || init.body === null ? undefined : await toBytes(init.body);
	if (body === undefined && input instanceof Request && method !== "GET" && method !== "HEAD") {
		body = new Uint8Array(await input.arrayBuffer());
	}
	if (body !== undefined && (method === "GET" || method === "HEAD")) {
		throw new TypeError("Request with GET or HEAD method cannot have a body");
	}
	return { url, method, headers, body };
}

async function fetchSafely(
	config: ResolvedOptions,
	input: string | URL | Request,
	init: RequestInit | undefined,
): Promise<Response> {
	const request = await prepareRequest(input, init);

	const callerSignal = init?.signal ?? undefined;
	const controller = new AbortController();
	let timedOut = false;
	let settled = false;
	const onCallerAbort = () => controller.abort();
	const timer = setTimeout(() => {
		timedOut = true;
		controller.abort();
	}, config.timeoutMs);
	callerSignal?.addEventListener("abort", onCallerAbort, { once: true });
	if (callerSignal?.aborted === true) {
		controller.abort();
	}

	// Releases the deadline and the caller listener. Called when the body is done or the call failed.
	const settle = (): void => {
		if (settled) {
			return;
		}
		settled = true;
		clearTimeout(timer);
		callerSignal?.removeEventListener("abort", onCallerAbort);
	};

	const toError = (error: unknown): unknown => {
		if (error instanceof SafeFetchError) {
			return error;
		}
		if (callerSignal?.aborted === true) {
			return callerSignal.reason;
		}
		if (timedOut) {
			return new SafeFetchError("TIMEOUT", `Request timed out after ${config.timeoutMs} ms`);
		}
		return new SafeFetchError("NETWORK_ERROR", "Network request failed");
	};

	try {
		let url = request.url;
		let method = request.method;
		let headers = request.headers;
		let body = request.body;
		let redirects = 0;

		for (;;) {
			const target = await resolveTarget(url, config, controller.signal);
			const outgoing: OutgoingRequest = { method, headers, body };
			const incoming = await sendRequest(target, outgoing, controller.signal);
			const status = incoming.statusCode ?? 0;

			if (!REDIRECT_STATUSES.has(status)) {
				return toResponse(incoming, {
					url,
					redirected: redirects > 0,
					method,
					maxBytes: config.maxBytes,
					onSettled: settle,
					toError,
				});
			}

			const location = incoming.headers.location;
			incoming.destroy();
			if (location === undefined) {
				throw new SafeFetchError(
					"REDIRECT_WITHOUT_LOCATION",
					"Redirect response has no Location header",
				);
			}
			if (redirects >= config.maxRedirects) {
				throw new SafeFetchError(
					"REDIRECT_LIMIT",
					`Redirect limit of ${config.maxRedirects} exceeded`,
				);
			}
			redirects++;

			// The next hop is validated from the top of the loop, including protocol, port, DNS and IP checks.
			const next = parseUrl(location, url);
			const nextHeaders: Record<string, string> = { ...headers };
			if (
				(status === 303 && method !== "HEAD") ||
				((status === 301 || status === 302) && method === "POST")
			) {
				method = "GET";
				body = undefined;
				delete nextHeaders["content-type"];
			}
			if (next.origin !== url.origin) {
				for (const name of CROSS_ORIGIN_HEADERS) {
					delete nextHeaders[name];
				}
			}
			headers = nextHeaders;
			url = next;
		}
	} catch (error) {
		settle();
		throw toError(error);
	}
}
