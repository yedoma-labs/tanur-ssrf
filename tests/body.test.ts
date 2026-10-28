import { describe, expect, it } from "vitest";
import { readBodyWithLimit, SafeFetchError } from "../src/index.js";

describe("readBodyWithLimit", () => {
	it("returns the complete body when it fits", async () => {
		const bytes = await readBodyWithLimit(new Response("hello"), 10);
		expect(new TextDecoder().decode(bytes)).toBe("hello");
	});

	it("accepts a body exactly at the limit", async () => {
		const bytes = await readBodyWithLimit(new Response("12345"), 5);
		expect(bytes.byteLength).toBe(5);
	});

	it("rejects a body one byte over the limit", async () => {
		const error = await readBodyWithLimit(new Response("123456"), 5).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(SafeFetchError);
		expect((error as SafeFetchError).code).toBe("BODY_TOO_LARGE");
	});

	it("returns an empty array for a response without body", async () => {
		const bytes = await readBodyWithLimit(new Response(null, { status: 204 }), 0);
		expect(bytes.byteLength).toBe(0);
	});

	it("rejects an invalid limit", async () => {
		await expect(readBodyWithLimit(new Response("x"), -1)).rejects.toBeInstanceOf(TypeError);
	});
});
