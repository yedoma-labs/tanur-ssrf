import type { ClientRequest, IncomingMessage, RequestOptions } from "node:http";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { LookupFunction } from "node:net";
import type { Readable, Transform } from "node:stream";
import { createBrotliDecompress, createGunzip, createInflate } from "node:zlib";
import { SafeFetchError } from "./errors.js";
import type { Target } from "./policy.js";

export interface OutgoingRequest {
	readonly method: string;
	readonly headers: Readonly<Record<string, string>>;
	readonly body: Uint8Array | undefined;
}

export interface ResponseContext {
	readonly url: URL;
	readonly redirected: boolean;
	readonly method: string;
	readonly maxBytes: number | undefined;
	/** Called once when the body is fully consumed, fails or is cancelled. Idempotent. */
	readonly onSettled: () => void;
	/** Maps any failure to the public error type. */
	readonly toError: (error: unknown) => unknown;
}

type ContentEncoding = "gzip" | "deflate" | "br";

const NULL_BODY_STATUS = new Set([204, 205, 304]);
const HOP_BY_HOP_REQUEST_HEADERS = ["host", "content-length", "transfer-encoding", "connection"];

/** Lookup that returns exactly the address validated in resolveTarget. Node never re-resolves. */
function pinnedLookup(target: Target): LookupFunction {
	return ((_hostname: string, options: { all?: boolean }, callback: unknown) => {
		const done = callback as (
			error: null,
			address: string | { address: string; family: number }[],
			family?: number,
		) => void;
		if (options.all === true) {
			done(null, [{ address: target.address, family: target.family }]);
		} else {
			done(null, target.address, target.family);
		}
	}) as LookupFunction;
}

function hostHeaderValue(target: Target): string {
	const host = target.hostname.includes(":") ? `[${target.hostname}]` : target.hostname;
	const isDefaultPort = target.port === (target.protocol === "https:" ? 443 : 80);
	return isDefaultPort ? host : `${host}:${target.port}`;
}

/**
 * Sends one request to the pinned address. `agent: false` prevents socket reuse,
 * so a socket validated under one policy can never serve a request under another.
 */
export function sendRequest(
	target: Target,
	request: OutgoingRequest,
	signal: AbortSignal,
): Promise<IncomingMessage> {
	return new Promise<IncomingMessage>((resolve, reject) => {
		const headers: Record<string, string> = { ...request.headers, host: hostHeaderValue(target) };
		if (request.body !== undefined) {
			headers["content-length"] = String(request.body.byteLength);
		}
		const options: RequestOptions & { lookup: LookupFunction; servername?: string } = {
			protocol: target.protocol,
			hostname: target.hostname,
			port: target.port,
			path: target.path,
			method: request.method,
			headers,
			agent: false,
			signal,
			lookup: pinnedLookup(target),
		};
		if (target.protocol === "https:" && !target.isIpLiteral) {
			options.servername = target.hostname;
		}
		const requestFn = (target.protocol === "https:" ? httpsRequest : httpRequest) as (
			options: RequestOptions,
			callback: (response: IncomingMessage) => void,
		) => ClientRequest;
		const outgoing = requestFn(options, resolve);
		outgoing.on("error", reject);
		outgoing.end(request.body);
	});
}

function parseContentEncoding(value: string | undefined): ContentEncoding | undefined {
	if (value === undefined) {
		return undefined;
	}
	const token = value.trim().toLowerCase();
	if (token === "" || token === "identity") {
		return undefined;
	}
	if (token === "gzip" || token === "x-gzip") {
		return "gzip";
	}
	if (token === "deflate") {
		return "deflate";
	}
	if (token === "br") {
		return "br";
	}
	throw new SafeFetchError("NETWORK_ERROR", "Unsupported content-encoding in response");
}

function createDecoder(encoding: ContentEncoding): Transform {
	switch (encoding) {
		case "gzip":
			return createGunzip();
		case "deflate":
			return createInflate();
		case "br":
			return createBrotliDecompress();
	}
}

function safeStatusText(message: string | undefined): string {
	return message !== undefined && /^[\x20-\x7e]*$/.test(message) ? message : "";
}

function createBodyStream(source: Readable, ctx: ResponseContext): ReadableStream<Uint8Array> {
	const iterator = source[Symbol.asyncIterator]();
	let received = 0;
	return new ReadableStream<Uint8Array>({
		async pull(controller) {
			try {
				const next = await iterator.next();
				if (next.done === true) {
					ctx.onSettled();
					controller.close();
					return;
				}
				const chunk = next.value as Uint8Array;
				received += chunk.byteLength;
				if (ctx.maxBytes !== undefined && received > ctx.maxBytes) {
					throw new SafeFetchError("BODY_TOO_LARGE", `Response body exceeds ${ctx.maxBytes} bytes`);
				}
				controller.enqueue(chunk);
			} catch (error) {
				ctx.onSettled();
				source.destroy();
				controller.error(ctx.toError(error));
			}
		},
		cancel() {
			ctx.onSettled();
			source.destroy();
		},
	});
}

/**
 * Converts a Node response into a fetch-compatible Response. Redirects must
 * already have been handled by the caller. Decodes gzip, deflate and br bodies.
 */
export function toResponse(incoming: IncomingMessage, ctx: ResponseContext): Response {
	const status = incoming.statusCode ?? 0;
	if (status < 200 || status > 599) {
		incoming.destroy();
		throw new SafeFetchError("NETWORK_ERROR", "Invalid HTTP status in response");
	}

	const headers = new Headers();
	for (const [name, value] of Object.entries(incoming.headers)) {
		if (value === undefined) {
			continue;
		}
		for (const item of Array.isArray(value) ? value : [value]) {
			headers.append(name, item);
		}
	}

	const bodyless = ctx.method === "HEAD" || NULL_BODY_STATUS.has(status);
	if (bodyless) {
		incoming.resume();
		ctx.onSettled();
		return buildResponse(null, status, incoming.statusMessage, headers, ctx);
	}

	const encoding = parseContentEncoding(incoming.headers["content-encoding"]);
	if (encoding === undefined) {
		const declared = Number(incoming.headers["content-length"]);
		if (ctx.maxBytes !== undefined && Number.isFinite(declared) && declared > ctx.maxBytes) {
			incoming.destroy();
			throw new SafeFetchError("BODY_TOO_LARGE", `Response body exceeds ${ctx.maxBytes} bytes`);
		}
	} else {
		// The body is decoded below, so the encoding and length headers no longer describe it.
		headers.delete("content-encoding");
		headers.delete("content-length");
	}

	// Errors are handled by the body stream; this listener only prevents an uncaught 'error' event.
	incoming.on("error", () => undefined);
	let source: Readable = incoming;
	if (encoding !== undefined) {
		const decoder = createDecoder(encoding);
		decoder.on("error", () => incoming.destroy());
		source = incoming.pipe(decoder);
		incoming.on("error", (error) => decoder.destroy(error));
	}

	return buildResponse(createBodyStream(source, ctx), status, incoming.statusMessage, headers, ctx);
}

function buildResponse(
	body: ReadableStream<Uint8Array> | null,
	status: number,
	statusMessage: string | undefined,
	headers: Headers,
	ctx: ResponseContext,
): Response {
	const response = new Response(body, {
		status,
		statusText: safeStatusText(statusMessage),
		headers,
	});
	Object.defineProperty(response, "url", { value: ctx.url.href });
	Object.defineProperty(response, "redirected", { value: ctx.redirected });
	return response;
}
