/**
 * Strict IP address parsing and range classification.
 *
 * Implemented locally (no ipaddr.js). Anything that is not an unambiguous
 * IPv4 or IPv6 literal is rejected by the parsers, so callers can fail closed.
 */

export type IpFamily = 4 | 6;

export interface ParsedIp {
	readonly family: IpFamily;
	readonly bytes: Uint8Array;
}

const IPV4_PART = /^(?:0|[1-9]\d{0,2})$/;
const IPV6_GROUP = /^[0-9a-fA-F]{1,4}$/;

/**
 * Parses a dotted-decimal IPv4 address. Leading zeros are rejected because
 * they are ambiguous (octal in some resolvers).
 */
export function parseIpv4(text: string): Uint8Array | undefined {
	const parts = text.split(".");
	if (parts.length !== 4) {
		return undefined;
	}
	const bytes = new Uint8Array(4);
	for (let index = 0; index < 4; index++) {
		const part = parts[index];
		if (part === undefined || !IPV4_PART.test(part)) {
			return undefined;
		}
		const value = Number(part);
		if (value > 255) {
			return undefined;
		}
		bytes[index] = value;
	}
	return bytes;
}

/** Parses 8 groups of 16 bits from a side of an IPv6 literal. */
function parseGroups(side: string, allowIpv4Tail: boolean): number[] | undefined {
	if (side === "") {
		return [];
	}
	const parts = side.split(":");
	const groups: number[] = [];
	for (let index = 0; index < parts.length; index++) {
		const part = parts[index];
		if (part === undefined) {
			return undefined;
		}
		if (allowIpv4Tail && index === parts.length - 1 && part.includes(".")) {
			const v4 = parseIpv4(part);
			if (v4 === undefined) {
				return undefined;
			}
			groups.push((byteAt(v4, 0) << 8) | byteAt(v4, 1), (byteAt(v4, 2) << 8) | byteAt(v4, 3));
			continue;
		}
		if (!IPV6_GROUP.test(part)) {
			return undefined;
		}
		groups.push(Number.parseInt(part, 16));
	}
	return groups;
}

/**
 * Parses an IPv6 literal (without brackets or zone id). Supports `::`
 * compression and an embedded dotted IPv4 tail. Zone ids are rejected.
 */
export function parseIpv6(text: string): Uint8Array | undefined {
	if (text.includes("%") || !text.includes(":")) {
		return undefined;
	}
	const compressionAt = text.indexOf("::");
	if (compressionAt !== text.lastIndexOf("::")) {
		return undefined;
	}

	let groups: number[];
	if (compressionAt === -1) {
		const all = parseGroups(text, true);
		if (all === undefined || all.length !== 8) {
			return undefined;
		}
		groups = all;
	} else {
		const head = parseGroups(text.slice(0, compressionAt), false);
		const tail = parseGroups(text.slice(compressionAt + 2), true);
		if (head === undefined || tail === undefined) {
			return undefined;
		}
		const missing = 8 - head.length - tail.length;
		if (missing < 1) {
			return undefined;
		}
		groups = [...head, ...new Array<number>(missing).fill(0), ...tail];
	}

	const bytes = new Uint8Array(16);
	for (let index = 0; index < 8; index++) {
		const group = groups[index] ?? 0;
		bytes[index * 2] = group >> 8;
		bytes[index * 2 + 1] = group & 0xff;
	}
	return bytes;
}

/** Parses an IPv4 or IPv6 literal. Returns undefined for anything else. */
export function parseIp(text: string): ParsedIp | undefined {
	if (text.includes(":")) {
		const bytes = parseIpv6(text);
		return bytes === undefined ? undefined : { family: 6, bytes };
	}
	const bytes = parseIpv4(text);
	return bytes === undefined ? undefined : { family: 4, bytes };
}

function byteAt(bytes: Uint8Array, index: number): number {
	return bytes[index] ?? 0;
}

function u32(a: number, b: number, c: number, d: number): number {
	return ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
}

interface Ipv4Range {
	readonly network: number;
	readonly prefix: number;
	readonly name: string;
}

const BLOCKED_IPV4: readonly Ipv4Range[] = [
	{ network: u32(0, 0, 0, 0), prefix: 8, name: "unspecified network (0.0.0.0/8)" },
	{ network: u32(10, 0, 0, 0), prefix: 8, name: "private (10.0.0.0/8)" },
	{ network: u32(100, 64, 0, 0), prefix: 10, name: "shared address space (100.64.0.0/10)" },
	{ network: u32(127, 0, 0, 0), prefix: 8, name: "loopback (127.0.0.0/8)" },
	{ network: u32(169, 254, 0, 0), prefix: 16, name: "link-local (169.254.0.0/16)" },
	{ network: u32(172, 16, 0, 0), prefix: 12, name: "private (172.16.0.0/12)" },
	{ network: u32(192, 0, 0, 0), prefix: 24, name: "IETF protocol assignments (192.0.0.0/24)" },
	{ network: u32(192, 0, 2, 0), prefix: 24, name: "documentation (192.0.2.0/24)" },
	{ network: u32(192, 168, 0, 0), prefix: 16, name: "private (192.168.0.0/16)" },
	{ network: u32(198, 18, 0, 0), prefix: 15, name: "benchmarking (198.18.0.0/15)" },
	{ network: u32(198, 51, 100, 0), prefix: 24, name: "documentation (198.51.100.0/24)" },
	{ network: u32(203, 0, 113, 0), prefix: 24, name: "documentation (203.0.113.0/24)" },
	{ network: u32(224, 0, 0, 0), prefix: 4, name: "multicast (224.0.0.0/4)" },
	{ network: u32(240, 0, 0, 0), prefix: 4, name: "reserved (240.0.0.0/4)" },
	{ network: u32(255, 255, 255, 255), prefix: 32, name: "broadcast (255.255.255.255)" },
];

function ipv4Value(bytes: Uint8Array): number {
	return u32(byteAt(bytes, 0), byteAt(bytes, 1), byteAt(bytes, 2), byteAt(bytes, 3));
}

function inPrefix(value: number, network: number, prefix: number): boolean {
	const mask = (0xffffffff << (32 - prefix)) >>> 0;
	return (value & mask) >>> 0 === (network & mask) >>> 0;
}

/** Returns the name of the blocked IPv4 range, or undefined if the address is public. */
function classifyIpv4(bytes: Uint8Array): string | undefined {
	const value = ipv4Value(bytes);
	for (const range of BLOCKED_IPV4) {
		if (inPrefix(value, range.network, range.prefix)) {
			return range.name;
		}
	}
	return undefined;
}

/** True if bytes[from..to) are all zero. */
function zeroBetween(bytes: Uint8Array, from: number, to: number): boolean {
	for (let index = from; index < to; index++) {
		if (byteAt(bytes, index) !== 0) {
			return false;
		}
	}
	return true;
}

function bytesEqual(bytes: Uint8Array, expected: readonly number[]): boolean {
	return expected.every((value, index) => byteAt(bytes, index) === value);
}

function classifyEmbeddedIpv4(bytes: Uint8Array, start: number, label: string): string | undefined {
	const reason = classifyIpv4(bytes.subarray(start, start + 4));
	return reason === undefined ? undefined : `${label}, embedded address in ${reason}`;
}

/**
 * Returns the name of the blocked IPv6 range, or undefined if the address is public.
 * Embedded IPv4 forms (mapped, NAT64, 6to4) are classified by their IPv4 address.
 */
function classifyIpv6(bytes: Uint8Array): string | undefined {
	if (zeroBetween(bytes, 0, 12)) {
		if (zeroBetween(bytes, 12, 15) && byteAt(bytes, 15) === 1) {
			return "loopback (::1)";
		}
		return "unspecified or IPv4-compatible (::/96)";
	}
	// IPv4-mapped ::ffff:0:0/96 is judged by the IPv4 address it wraps.
	if (zeroBetween(bytes, 0, 10) && bytesEqual(bytes.subarray(10, 12), [0xff, 0xff])) {
		const reason = classifyIpv4(bytes.subarray(12, 16));
		return reason === undefined ? undefined : `IPv4-mapped, ${reason}`;
	}
	// IPv4-translated ::ffff:0:0:0/96 (SIIT) is never routed to public addresses.
	if (zeroBetween(bytes, 0, 8) && bytesEqual(bytes.subarray(8, 12), [0xff, 0xff, 0x00, 0x00])) {
		return "IPv4-translated (::ffff:0:0:0/96)";
	}
	// NAT64 well-known prefix 64:ff9b::/96.
	if (bytesEqual(bytes, [0x00, 0x64, 0xff, 0x9b]) && zeroBetween(bytes, 4, 12)) {
		return classifyEmbeddedIpv4(bytes, 12, "NAT64 (64:ff9b::/96)");
	}
	// 6to4 2002::/16 carries an IPv4 address in bytes 2..5.
	if (bytesEqual(bytes, [0x20, 0x02])) {
		return classifyEmbeddedIpv4(bytes, 2, "6to4 (2002::/16)");
	}
	// Teredo 2001::/32 obfuscates client addresses; not needed by server-side fetches.
	if (bytesEqual(bytes, [0x20, 0x01, 0x00, 0x00])) {
		return "Teredo (2001::/32)";
	}
	if (bytesEqual(bytes, [0x01, 0x00]) && zeroBetween(bytes, 2, 8)) {
		return "discard-only (100::/64)";
	}
	if (bytesEqual(bytes, [0x20, 0x01, 0x0d, 0xb8])) {
		return "documentation (2001:db8::/32)";
	}
	const first = byteAt(bytes, 0);
	const second = byteAt(bytes, 1);
	if ((first & 0xfe) === 0xfc) {
		return "unique local (fc00::/7)";
	}
	if (first === 0xfe && (second & 0xc0) === 0x80) {
		return "link-local (fe80::/10)";
	}
	if (first === 0xfe && (second & 0xc0) === 0xc0) {
		return "site-local (fec0::/10)";
	}
	if (first === 0xff) {
		return "multicast (ff00::/8)";
	}
	return undefined;
}

/**
 * Returns a description of the blocked range the address falls into, or
 * undefined if the address is globally routable (as far as this list knows).
 */
export function getBlockedRange(ip: ParsedIp): string | undefined {
	return ip.family === 4 ? classifyIpv4(ip.bytes) : classifyIpv6(ip.bytes);
}
