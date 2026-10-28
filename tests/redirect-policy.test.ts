import { EventEmitter } from "node:events";
import type { ClientRequest, IncomingMessage, RequestOptions } from "node:http";
import * as http from "node:http";
import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import type { Resolver } from "../src/index.js";
import { createSafeFetch, SafeFetchError } from "../src/index.js";

/*
 * The first hop answers with a redirect from a fake response, so the first hop may use
 * a public-looking address that is never really contacted. This makes it possible to
 * test that a redirect into private space is rejected before any socket opens.
 */

vi.mock("node:http", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:http")>();
	return { ...actual, request: vi.fn() };
});

const requestMock = vi.mocked(http.request);

function redirectResponse(location: string | undefined, status = 302): IncomingMessage {
	const response = new PassThrough() as unknown as IncomingMessage;
	Object.assign(response, {
		statusCode: status,
		statusMessage: "Found",
		headers: location === undefined ? {} : { location },
	});
	return response;
}

/** Each outgoing request consumes the next queued response. Records the requested options. */
function queueResponses(responses: IncomingMessage[]): RequestOptions[] {
	const seen: RequestOptions[] = [];
	requestMock.mockImplementation(((
		options: RequestOptions,
		callback?: (res: IncomingMessage) => void,
	) => {
		seen.push(options);
		const outgoing = new EventEmitter() as EventEmitter & { end: (body?: unknown) => void };
		outgoing.end = () => {
			const next = responses.shift();
			if (next === undefined) {
				throw new Error("test setup: no queued response left");
			}
			callback?.(next);
		};
		return outgoing as unknown as ClientRequest;
	}) as unknown as typeof http.request);
	return seen;
}

const publicLooking: Resolver = async () => [{ address: "93.184.216.34", family: 4 }];

/** Calls the lookup callback that Node would use to open the socket, and returns the address it yields. */
function pinnedAddress(options: RequestOptions | undefined): Promise<unknown> {
	const lookup = (options as { lookup?: unknown } | undefined)?.lookup as (
		hostname: string,
		opts: { all?: boolean },
		callback: (error: unknown, address: unknown) => void,
	) => void;
	return new Promise((resolve) => {
		lookup("front.example.test", {}, (_error, address) => resolve(address));
	});
}

async function codeOf(promise: Promise<unknown>): Promise<string> {
	try {
		await promise;
		return "resolved";
	} catch (error) {
		return error instanceof SafeFetchError ? error.code : `unexpected: ${String(error)}`;
	}
}

describe("redirect re-validation (no sockets opened)", () => {
	it("rejects a redirect into private address space before connecting to it", async () => {
		requestMock.mockReset();
		const seen = queueResponses([redirectResponse("http://10.0.0.5/admin")]);
		const fetchSafe = createSafeFetch({ resolver: publicLooking });
		expect(await codeOf(fetchSafe("http://front.example.test/"))).toBe("BLOCKED_ADDRESS");
		expect(seen).toHaveLength(1);
		// The socket is pinned to the validated public address, not to a re-resolved one.
		expect(await pinnedAddress(seen[0])).toBe("93.184.216.34");
	});

	it("rejects a redirect to the metadata endpoint", async () => {
		requestMock.mockReset();
		const seen = queueResponses([redirectResponse("http://169.254.169.254/latest/meta-data/")]);
		const fetchSafe = createSafeFetch({ resolver: publicLooking });
		expect(await codeOf(fetchSafe("http://front.example.test/"))).toBe("BLOCKED_ADDRESS");
		expect(seen).toHaveLength(1);
	});

	it("rejects a redirect to a file: URL", async () => {
		requestMock.mockReset();
		const seen = queueResponses([redirectResponse("file:///etc/passwd")]);
		const fetchSafe = createSafeFetch({ resolver: publicLooking });
		expect(await codeOf(fetchSafe("http://front.example.test/"))).toBe("PROTOCOL_NOT_ALLOWED");
		expect(seen).toHaveLength(1);
	});

	it("re-resolves a redirect hostname and pins the new answer", async () => {
		requestMock.mockReset();
		const resolver = vi
			.fn<Resolver>()
			.mockResolvedValueOnce([{ address: "93.184.216.34", family: 4 }])
			.mockResolvedValueOnce([{ address: "10.1.1.1", family: 4 }]);
		const seen = queueResponses([redirectResponse("http://second.example.test/x")]);
		const fetchSafe = createSafeFetch({ resolver });
		expect(await codeOf(fetchSafe("http://first.example.test/"))).toBe("BLOCKED_ADDRESS");
		expect(resolver).toHaveBeenCalledTimes(2);
		expect(resolver).toHaveBeenLastCalledWith("second.example.test");
		expect(seen).toHaveLength(1);
	});

	it("reports REDIRECT_LIMIT without an extra request after the limit", async () => {
		requestMock.mockReset();
		const seen = queueResponses([
			redirectResponse("http://front.example.test/a"),
			redirectResponse("http://front.example.test/b"),
			redirectResponse("http://front.example.test/c"),
		]);
		const fetchSafe = createSafeFetch({ resolver: publicLooking, maxRedirects: 2 });
		expect(await codeOf(fetchSafe("http://front.example.test/"))).toBe("REDIRECT_LIMIT");
		expect(seen).toHaveLength(3);
	});

	it("uses a fresh socket per request by disabling the agent", async () => {
		requestMock.mockReset();
		const seen = queueResponses([redirectResponse(undefined)]);
		const fetchSafe = createSafeFetch({ resolver: publicLooking });
		await fetchSafe("http://front.example.test/").catch(() => undefined);
		expect(seen[0]?.agent).toBe(false);
	});
});
