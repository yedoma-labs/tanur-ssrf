import { describe, expect, it, vi } from "vitest";
import type { Resolver } from "../src/index.js";
import { createSafeFetch, SafeFetchError } from "../src/index.js";

/** Resolves to the error code, or "resolved" when the call succeeds. Never opens a socket in these tests. */
async function codeOf(promise: Promise<unknown>): Promise<string> {
	try {
		await promise;
		return "resolved";
	} catch (error) {
		return error instanceof SafeFetchError ? error.code : `unexpected: ${String(error)}`;
	}
}

function resolverReturning(addresses: readonly string[]): Resolver {
	return vi.fn(async () =>
		addresses.map((address) => ({ address, family: address.includes(":") ? 6 : 4 })),
	);
}

describe("protocol, URL and port policy", () => {
	const resolver = resolverReturning(["127.0.0.1"]);
	const fetchSafe = createSafeFetch({ resolver });

	it.each([
		"file:///etc/passwd",
		"ftp://example.test/file",
		"gopher://example.test/",
		"javascript:alert(1)",
	])("rejects protocol of %s", async (url) => {
		expect(await codeOf(fetchSafe(url))).toBe("PROTOCOL_NOT_ALLOWED");
	});

	it("rejects http when only https is allowed", async () => {
		const httpsOnly = createSafeFetch({ allowedProtocols: ["https:"], resolver });
		expect(await codeOf(httpsOnly("http://example.test/"))).toBe("PROTOCOL_NOT_ALLOWED");
	});

	it.each(["not a url", "/relative/path", "http://", "https://exa mple.test/"])(
		"rejects invalid URL %j",
		async (url) => {
			expect(await codeOf(fetchSafe(url))).toBe("INVALID_URL");
		},
	);

	it("rejects URLs with credentials without echoing them", async () => {
		const error = await fetchSafe("https://user:hunter2@example.test/").catch((e: unknown) => e);
		expect(error).toBeInstanceOf(SafeFetchError);
		expect((error as SafeFetchError).code).toBe("INVALID_URL");
		expect((error as SafeFetchError).message).not.toMatch(/hunter2|user/);
	});

	it("rejects a username without password", async () => {
		expect(await codeOf(fetchSafe("https://user@example.test/"))).toBe("INVALID_URL");
	});

	it("rejects ports outside the default allowlist before DNS", async () => {
		const spy = vi.fn(resolver);
		const guarded = createSafeFetch({ resolver: spy });
		expect(await codeOf(guarded("http://example.test:8080/"))).toBe("PORT_NOT_ALLOWED");
		expect(spy).not.toHaveBeenCalled();
	});

	it("allows explicitly listed ports", async () => {
		const guarded = createSafeFetch({
			allowedPorts: [8080],
			resolver: resolverReturning(["10.0.0.1"]),
		});
		expect(await codeOf(guarded("http://example.test:8080/"))).toBe("BLOCKED_ADDRESS");
	});
});

describe("hostname policy", () => {
	it.each([
		"http://localhost/",
		"http://LOCALHOST/",
		"http://localhost./",
		"http://api.localhost/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://service.internal/",
		"http://internal/",
	])("blocks %s before DNS", async (url) => {
		const resolver = vi.fn(resolverReturning(["93.184.216.34"]));
		const fetchSafe = createSafeFetch({ resolver, allowPrivateNetworks: true });
		expect(await codeOf(fetchSafe(url))).toBe("BLOCKED_HOSTNAME");
		expect(resolver).not.toHaveBeenCalled();
	});

	it("replaces the default blocklist when one is given", async () => {
		const resolver = resolverReturning(["10.0.0.1"]);
		const fetchSafe = createSafeFetch({ resolver, blockedHostnames: ["evil.test"] });
		expect(await codeOf(fetchSafe("http://evil.test/"))).toBe("BLOCKED_HOSTNAME");
		expect(await codeOf(fetchSafe("http://localhost/"))).toBe("BLOCKED_ADDRESS");
	});
});

describe("IP literal policy", () => {
	const resolver = vi.fn(resolverReturning(["93.184.216.34"]));
	const fetchSafe = createSafeFetch({ resolver });

	it.each([
		"http://127.0.0.1/",
		"http://0x7f000001/",
		"http://2130706433/",
		"http://0177.0.0.1/",
		"http://127.1/",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1/",
		"http://192.168.1.1/",
		"http://0.0.0.0/",
		"http://[::1]/",
		"http://[::]/",
		"http://[fd00::1]/",
		"http://[fe80::1]/",
		"http://[::ffff:127.0.0.1]/",
		"http://[::ffff:7f00:1]/",
		"http://[::ffff:a9fe:a9fe]/",
		"http://[64:ff9b::a9fe:a9fe]/",
	])("blocks %s without a DNS lookup", async (url) => {
		resolver.mockClear();
		expect(await codeOf(fetchSafe(url))).toBe("BLOCKED_ADDRESS");
		expect(resolver).not.toHaveBeenCalled();
	});
});

describe("DNS answer policy", () => {
	it("maps a resolver error to DNS_FAILURE", async () => {
		const fetchSafe = createSafeFetch({
			resolver: async () => {
				throw new Error("ENOTFOUND example.test");
			},
		});
		expect(await codeOf(fetchSafe("http://example.test/"))).toBe("DNS_FAILURE");
	});

	it("maps an empty answer to DNS_FAILURE", async () => {
		const fetchSafe = createSafeFetch({ resolver: async () => [] });
		expect(await codeOf(fetchSafe("http://example.test/"))).toBe("DNS_FAILURE");
	});

	it("rejects the whole hop when any resolved address is blocked", async () => {
		const resolver = vi.fn(resolverReturning(["93.184.216.34", "10.0.0.7"]));
		const fetchSafe = createSafeFetch({ resolver });
		expect(await codeOf(fetchSafe("http://example.test/"))).toBe("BLOCKED_ADDRESS");
		expect(resolver).toHaveBeenCalledTimes(1);
	});

	it("rejects a rebinding answer that points at a private address", async () => {
		const resolver = vi.fn(resolverReturning(["169.254.169.254"]));
		const fetchSafe = createSafeFetch({ resolver });
		expect(await codeOf(fetchSafe("https://rebind.example.test/"))).toBe("BLOCKED_ADDRESS");
		expect(resolver).toHaveBeenCalledTimes(1);
	});

	it.each([["not-an-ip"], ["example.com"], ["999.1.1.1"]])(
		"rejects non-IP resolver value %j",
		async (value) => {
			const fetchSafe = createSafeFetch({ resolver: resolverReturning([value]) });
			expect(await codeOf(fetchSafe("http://example.test/"))).toBe("BLOCKED_ADDRESS");
		},
	);
});

describe("option validation", () => {
	it.each([
		[{ timeoutMs: 0 }],
		[{ timeoutMs: Number.NaN }],
		[{ maxRedirects: -1 }],
		[{ maxRedirects: 1.5 }],
		[{ maxBytes: -1 }],
		[{ allowedPorts: [70000] }],
		[{ allowedProtocols: ["HTTP:"] }],
		[{ resolver: "not-a-function" as unknown as Resolver }],
	])("throws TypeError for %j", (options) => {
		expect(() => createSafeFetch(options)).toThrow(TypeError);
	});
});
