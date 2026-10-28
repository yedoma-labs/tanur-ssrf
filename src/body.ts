import { SafeFetchError } from "./errors.js";

/**
 * Reads a Response body into memory, failing once more than `maxBytes` bytes arrive.
 * The stream is cancelled at the limit, so an oversized body is not buffered.
 */
export async function readBodyWithLimit(response: Response, maxBytes: number): Promise<Uint8Array> {
	if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
		throw new TypeError("maxBytes must be a non-negative integer");
	}
	if (response.body === null) {
		return new Uint8Array(0);
	}

	const reader = response.body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) {
			break;
		}
		total += value.byteLength;
		if (total > maxBytes) {
			await reader.cancel();
			throw new SafeFetchError("BODY_TOO_LARGE", `Response body exceeds ${maxBytes} bytes`);
		}
		chunks.push(value);
	}

	const result = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		result.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return result;
}
