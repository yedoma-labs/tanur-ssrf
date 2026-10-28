import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { gzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { Resolver } from "../src/index.js";
import { createSafeFetch, SafeFetchError } from "../src/index.js";

/*
 * These tests use a loopback server only. Hostnames such as app.test are fake: the
 * injected resolver maps them to 127.0.0.1, so the pinned connection still goes to the
 * local server. No real DNS query and no external connection happens.
 */

let hits = 0;
let otherPort = 0;

function handler(req: IncomingMessage, res: ServerResponse): void {
	hits++;
	const url = new URL(req.url ?? "/", "http://localhost");
	const redirect = (status: number, location: string): void => {
		res.writeHead(status, { location });
		res.end();
	};
	switch (url.pathname) {
		case "/hello":
			res.setHeader("content-type", "text/plain");
			res.end(req.headers.host ?? "");
			return;
		case "/final":
			res.end("final");
			return;
		case "/redirect":
			redirect(302, "/final");
			return;
		case "/loop":
			redirect(302, "/loop");
			return;
		case "/noloc":
			res.writeHead(302);
			res.end();
			return;
		case "/to-localhost":
			redirect(302, `http://localhost:${otherPort}/hello`);
			return;
		case "/to-port":
			redirect(302, "http://app.test:9/");
			return;
		case "/see-other":
			redirect(303, "/echo");
			return;
		case "/temporary":
			redirect(307, "/echo");
			return;
		case "/same-origin-echo":
			redirect(302, "/echo");
			return;
		case "/cross-origin-echo":
			redirect(302, `http://127.0.0.1:${otherPort}/echo`);
			return;
		case "/echo": {
			const chunks: Buffer[] = [];
			req.on("data", (chunk: Buffer) => chunks.push(chunk));
			req.on("end", () => {
				res.setHeader("content-type", "application/json");
				res.end(
					JSON.stringify({
						method: req.method,
						body: Buffer.concat(chunks).toString("utf8"),
						authorization: req.headers.authorization ?? null,
					}),
				);
			});
			return;
		}
		case "/big-length":
			res.setHeader("content-length", "10");
			res.end("0123456789");
			return;
		case "/big-chunked":
			res.write("0123456789");
			res.end();
			return;
		case "/gzip": {
			res.setHeader("content-encoding", "gzip");
			res.setHeader("content-type", "text/plain");
			res.end(gzipSync("hello gzip"));
			return;
		}
		case "/no-content":
			res.writeHead(204);
			res.end();
			return;
		case "/hang":
			// Never answers; the caller's timeout or abort must end the request.
			return;
		default:
			res.writeHead(404);
			res.end();
	}
}

function listen(server: Server): Promise<number> {
	return new Promise((resolve) => {
		server.listen(0, "127.0.0.1", () => {
			resolve((server.address() as AddressInfo).port);
		});
	});
}

function staticResolver(addresses: readonly string[]): Resolver {
	return vi.fn(async () =>
		addresses.map((address) => ({ address, family: address.includes(":") ? 6 : 4 })),
	);
}

let server: Server;
let other: Server;
let port = 0;

beforeAll(async () => {
	server = createServer(handler);
	other = createServer(handler);
	port = await listen(server);
	otherPort = await listen(other);
});

afterAll(() => {
	server.closeAllConnections();
	other.closeAllConnections();
	server.close();
	other.close();
});

function localFetch(options: Partial<Parameters<typeof createSafeFetch>[0]> = {}) {
	return createSafeFetch({
		allowPrivateNetworks: true,
		allowedPorts: [port, otherPort],
		resolver: staticResolver(["127.0.0.1"]),
		...options,
	});
}

describe("pinned connection and Host header", () => {
	it("connects to the resolved address and sends the original Host header", async () => {
		const resolver = vi.fn(staticResolver(["127.0.0.1"]));
		const fetchSafe = localFetch({ resolver });
		const response = await fetchSafe(`http://app.test:${port}/hello`);
		expect(await response.text()).toBe(`app.test:${port}`);
		expect(resolver).toHaveBeenCalledTimes(1);
		expect(resolver).toHaveBeenCalledWith("app.test");
	});

	it("does not re-resolve even if DNS would answer differently later", async () => {
		const resolver = vi
			.fn<Resolver>()
			.mockResolvedValueOnce([{ address: "127.0.0.1", family: 4 }])
			.mockResolvedValue([{ address: "10.9.9.9", family: 4 }]);
		const fetchSafe = localFetch({ resolver });
		const response = await fetchSafe(`http://rebind.test:${port}/hello`);
		expect(await response.text()).toBe(`rebind.test:${port}`);
		expect(resolver).toHaveBeenCalledTimes(1);
	});

	it("normalizes case and the trailing dot in the hostname and Host header", async () => {
		const resolver = vi.fn(staticResolver(["127.0.0.1"]));
		const fetchSafe = localFetch({ resolver });
		const response = await fetchSafe(`http://APP.test.:${port}/hello`);
		expect(await response.text()).toBe(`app.test:${port}`);
		expect(resolver).toHaveBeenCalledWith("app.test");
	});

	it("rejects a private answer before connecting", async () => {
		const before = hits;
		const fetchSafe = createSafeFetch({
			allowedPorts: [port],
			resolver: staticResolver(["127.0.0.1"]),
		});
		await expect(fetchSafe(`http://app.test:${port}/hello`)).rejects.toMatchObject({
			code: "BLOCKED_ADDRESS",
		});
		expect(hits).toBe(before);
	});

	it("rejects a mixed answer with a public and a loopback address without connecting", async () => {
		const before = hits;
		const fetchSafe = createSafeFetch({
			allowedPorts: [port],
			resolver: staticResolver(["93.184.216.34", "127.0.0.1"]),
		});
		await expect(fetchSafe(`http://mixed.test:${port}/hello`)).rejects.toMatchObject({
			code: "BLOCKED_ADDRESS",
		});
		expect(hits).toBe(before);
	});
});

describe("redirects", () => {
	it("follows relative redirects against the current URL", async () => {
		const response = await localFetch()(`http://app.test:${port}/redirect`);
		expect(await response.text()).toBe("final");
		expect(response.url).toBe(`http://app.test:${port}/final`);
		expect(response.redirected).toBe(true);
	});

	it("reports REDIRECT_LIMIT for a redirect loop", async () => {
		const fetchSafe = localFetch({ maxRedirects: 3 });
		await expect(fetchSafe(`http://app.test:${port}/loop`)).rejects.toMatchObject({
			code: "REDIRECT_LIMIT",
		});
	});

	it("reports REDIRECT_WITHOUT_LOCATION", async () => {
		await expect(localFetch()(`http://app.test:${port}/noloc`)).rejects.toMatchObject({
			code: "REDIRECT_WITHOUT_LOCATION",
		});
	});

	it("re-validates a redirect to a blocked hostname", async () => {
		const fetchSafe = createSafeFetch({
			allowPrivateNetworks: true,
			allowedPorts: [port, otherPort],
			resolver: staticResolver(["127.0.0.1"]),
		});
		await expect(fetchSafe(`http://app.test:${port}/to-localhost`)).rejects.toMatchObject({
			code: "BLOCKED_HOSTNAME",
		});
	});

	it("re-validates the port of a redirect target", async () => {
		await expect(localFetch()(`http://app.test:${port}/to-port`)).rejects.toMatchObject({
			code: "PORT_NOT_ALLOWED",
		});
	});

	it("turns POST into GET and drops the body on 303", async () => {
		const response = await localFetch()(`http://app.test:${port}/see-other`, {
			method: "POST",
			body: "payload",
		});
		expect(await response.json()).toEqual({ method: "GET", body: "", authorization: null });
	});

	it("keeps method and body on 307", async () => {
		const response = await localFetch()(`http://app.test:${port}/temporary`, {
			method: "POST",
			body: "payload",
		});
		expect(await response.json()).toEqual({ method: "POST", body: "payload", authorization: null });
	});

	it("keeps Authorization on a same-origin redirect", async () => {
		const response = await localFetch()(`http://app.test:${port}/same-origin-echo`, {
			headers: { authorization: "Bearer token" },
		});
		expect((await response.json()).authorization).toBe("Bearer token");
	});

	it("drops Authorization on a cross-origin redirect", async () => {
		const response = await localFetch()(`http://app.test:${port}/cross-origin-echo`, {
			headers: { authorization: "Bearer token" },
		});
		expect((await response.json()).authorization).toBeNull();
	});
});

describe("request and response handling", () => {
	it("sends a string body with its content length", async () => {
		const response = await localFetch()(`http://app.test:${port}/echo`, {
			method: "POST",
			body: "abc",
		});
		expect(await response.json()).toEqual({ method: "POST", body: "abc", authorization: null });
	});

	it("rejects a request body type it cannot replay across redirects", async () => {
		await expect(
			localFetch()(`http://app.test:${port}/echo`, {
				method: "POST",
				body: new ReadableStream<Uint8Array>(),
			}),
		).rejects.toBeInstanceOf(TypeError);
	});

	it("decodes gzip bodies and removes the encoding headers", async () => {
		const response = await localFetch()(`http://app.test:${port}/gzip`);
		expect(await response.text()).toBe("hello gzip");
		expect(response.headers.get("content-encoding")).toBeNull();
	});

	it("returns a 204 response without a body", async () => {
		const response = await localFetch()(`http://app.test:${port}/no-content`);
		expect(response.status).toBe(204);
		expect(response.body).toBeNull();
	});

	it("rejects a declared body larger than maxBytes", async () => {
		const fetchSafe = localFetch({ maxBytes: 5 });
		await expect(fetchSafe(`http://app.test:${port}/big-length`)).rejects.toMatchObject({
			code: "BODY_TOO_LARGE",
		});
	});

	it("rejects a streamed body larger than maxBytes while it is read", async () => {
		const fetchSafe = localFetch({ maxBytes: 5 });
		const response = await fetchSafe(`http://app.test:${port}/big-chunked`);
		await expect(response.text()).rejects.toMatchObject({ code: "BODY_TOO_LARGE" });
	});
});

describe("timeouts, aborts and DNS failures", () => {
	it("reports TIMEOUT when the server never answers", async () => {
		const fetchSafe = localFetch({ timeoutMs: 150 });
		await expect(fetchSafe(`http://app.test:${port}/hang`)).rejects.toMatchObject({
			code: "TIMEOUT",
		});
	});

	it("rethrows the caller's abort reason instead of a SafeFetchError", async () => {
		const controller = new AbortController();
		const pending = localFetch()(`http://app.test:${port}/hang`, { signal: controller.signal });
		setTimeout(() => controller.abort(), 50);
		const error = await pending.catch((e: unknown) => e);
		expect(error).not.toBeInstanceOf(SafeFetchError);
		expect((error as Error).name).toBe("AbortError");
	});

	it("reports DNS_FAILURE when the resolver throws", async () => {
		const fetchSafe = createSafeFetch({
			allowPrivateNetworks: true,
			allowedPorts: [port],
			resolver: async () => {
				throw new Error("ENOTFOUND");
			},
		});
		await expect(fetchSafe(`http://missing.test:${port}/hello`)).rejects.toMatchObject({
			code: "DNS_FAILURE",
		});
	});
});
