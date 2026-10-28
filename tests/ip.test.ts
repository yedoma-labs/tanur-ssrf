import { describe, expect, it } from "vitest";
import { getBlockedRange, parseIp, parseIpv4, parseIpv6 } from "../src/ip.js";

function blocked(text: string): string | undefined {
	const ip = parseIp(text);
	if (ip === undefined) {
		throw new Error(`test setup: ${text} did not parse`);
	}
	return getBlockedRange(ip);
}

describe("parseIpv4", () => {
	it("parses dotted decimal", () => {
		expect([...(parseIpv4("192.168.1.10") ?? [])]).toEqual([192, 168, 1, 10]);
	});

	it.each([
		"010.0.0.1",
		"1.2.3",
		"1.2.3.4.5",
		"256.0.0.1",
		"1.2.3.-1",
		" 1.2.3.4",
		"1.2.3.4 ",
		"0x7f.0.0.1",
		"",
	])("rejects %j", (text) => {
		expect(parseIpv4(text)).toBeUndefined();
	});
});

describe("parseIpv6", () => {
	it.each(["::1", "::", "2001:db8::1", "fe80::1", "2606:4700:4700::1111", "1:2:3:4:5:6:7:8"])(
		"parses %s",
		(text) => {
			expect(parseIpv6(text)).toHaveLength(16);
		},
	);

	it("parses an embedded IPv4 tail", () => {
		expect([...(parseIpv6("::ffff:127.0.0.1") ?? [])].slice(10)).toEqual([
			0xff, 0xff, 127, 0, 0, 1,
		]);
	});

	it.each([
		"[::1]",
		"fe80::1%eth0",
		":::",
		"1::2::3",
		"1:2:3:4:5:6:7:8:9",
		"1:2:3:4:5:6:7",
		"::1::",
		":1::2",
		"::g",
		"::1.2.3",
		"1.2.3.4::1",
	])("rejects %j", (text) => {
		expect(parseIpv6(text)).toBeUndefined();
	});
});

describe("getBlockedRange: IPv4", () => {
	it.each([
		["0.0.0.0", "unspecified"],
		["10.1.2.3", "private"],
		["100.64.0.1", "shared"],
		["100.127.255.255", "shared"],
		["127.0.0.1", "loopback"],
		["169.254.169.254", "link-local"],
		["172.16.0.1", "private"],
		["172.31.255.255", "private"],
		["192.0.0.8", "IETF"],
		["192.168.0.1", "private"],
		["198.18.0.1", "benchmarking"],
		["198.19.255.255", "benchmarking"],
		["224.0.0.1", "multicast"],
		["240.0.0.1", "reserved"],
		["255.255.255.255", "broadcast"],
	])("blocks %s (%s)", (text) => {
		expect(blocked(text)).toBeDefined();
	});

	it.each([
		"8.8.8.8",
		"1.1.1.1",
		"172.15.255.255",
		"172.32.0.0",
		"100.63.255.255",
		"198.20.0.1",
		"9.255.255.255",
	])("allows public %s", (text) => {
		expect(blocked(text)).toBeUndefined();
	});
});

describe("getBlockedRange: IPv6", () => {
	it.each([
		"::",
		"::1",
		"fc00::1",
		"fd12:3456:789a::1",
		"fe80::1",
		"febf::1",
		"ff02::1",
		"fec0::1",
		"::127.0.0.1",
		"100::1",
		"2001:db8::1",
		"3fff::1",
		"3fff:0fff:ffff::1",
		"64:ff9b:1::1",
		"64:ff9b:1:ffff::808:808",
	])("blocks %s", (text) => {
		expect(blocked(text)).toBeDefined();
	});

	it.each([
		["::ffff:127.0.0.1", "loopback"],
		["::ffff:7f00:1", "loopback"],
		["::FFFF:169.254.169.254", "link-local"],
		["::ffff:a9fe:a9fe", "link-local"],
		["::ffff:10.0.0.1", "private"],
		["::ffff:0:127.0.0.1", "IPv4-translated"],
		["64:ff9b::a9fe:a9fe", "metadata"],
		["2002:a9fe:a9fe::1", "metadata"],
		["2002:7f00:1::", "loopback"],
	])("blocks embedded IPv4 form %s (%s)", (text) => {
		expect(blocked(text)).toBeDefined();
	});

	it.each([
		"::ffff:8.8.8.8",
		"::ffff:808:808",
		"2001:4860:4860::8888",
		"2606:4700:4700::1111",
		"2002:808:808::1",
		"3fff:1000::1",
		"64:ff9b::808:808",
	])("allows public %s", (text) => {
		expect(blocked(text)).toBeUndefined();
	});
});
