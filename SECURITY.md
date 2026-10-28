# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x     | :white_check_mark: latest release only |

Until 1.0, fixes are released in the next minor version.

## Security Model

`@yedoma-labs/tanur-ssrf` is a server-side library that fetches URLs which may be supplied by untrusted users. It protects the application from SSRF through the following assumptions:

- **URLs, redirect targets and DNS answers are untrusted.** Every hop is validated.
- **Options are trusted.** They are developer code. Do not derive `allowPrivateNetworks`, `allowedPorts`, `blockedHostnames` or `resolver` from user input.
- **The library runs in Node.js.** It does not sandbox the process, and it does not protect against OS, kernel or network-stack vulnerabilities.
- **No proxy support.** Environment proxies are not honored, and a configured proxy is outside this policy.

See the README "Guarantees" and "Limits" sections for the detailed list.

## Known Limitations

1. **Response body content is not inspected.** A permitted server can return any body. Use `maxBytes` and validate content in your application.
2. **Hostname blocklist is advisory.** The IP checks are the enforcement layer. Replacing `blockedHostnames` removes the hostname layer.
3. **Reserved ranges are a fixed list.** They reflect IANA allocations at the time of release. New or unusual encodings should be reported.
4. **TLS verification uses the Node.js trust store.** Custom CA configuration is not exposed by this library.

## Reporting a Vulnerability

Please report vulnerabilities privately through GitHub Private Vulnerability Reporting: open the repository's **Security** tab and choose **Report a vulnerability**.

Please include:

- A description of the issue and its impact (for example: an address or hostname that bypasses a check)
- Steps or a minimal reproduction, using a loopback server or an injected resolver where possible
- The affected version and Node.js version
- A suggested fix, if you have one

We aim to acknowledge reports within 48 hours and to coordinate disclosure with the reporter.

Please do not open public issues for suspected bypasses before a fix is available.

## Security Best Practices for Users

1. **Keep `allowPrivateNetworks` at its default `false`** for any URL that comes from a user.
2. **Always set `maxBytes` and `timeoutMs`** for user-supplied targets.
3. **Keep the default `blockedHostnames`** when you pass your own list.
4. **Read the body with `readBodyWithLimit`** or with `maxBytes`, never with an unbounded `response.text()`.
5. **Use network egress controls** for high-risk workloads. This library reduces SSRF inside the process and does not replace a firewall.

## Dependency Security

This library has **zero runtime dependencies**. It uses only `node:*` built-in modules. Run `pnpm audit` regularly for development dependencies.

## License

MIT. See [LICENSE](LICENSE).
