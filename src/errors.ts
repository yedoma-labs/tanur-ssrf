export type SafeFetchErrorCode =
	| "PROTOCOL_NOT_ALLOWED"
	| "PORT_NOT_ALLOWED"
	| "INVALID_URL"
	| "BLOCKED_HOSTNAME"
	| "BLOCKED_ADDRESS"
	| "DNS_FAILURE"
	| "REDIRECT_LIMIT"
	| "REDIRECT_WITHOUT_LOCATION"
	| "TIMEOUT"
	| "BODY_TOO_LARGE"
	| "NETWORK_ERROR";

/**
 * Typed error thrown by the safe fetch. Messages never contain the URL, its
 * query string or any credentials; they only name the blocked host or address.
 */
export class SafeFetchError extends Error {
	readonly code: SafeFetchErrorCode;

	constructor(code: SafeFetchErrorCode, message: string) {
		super(message);
		this.name = "SafeFetchError";
		this.code = code;
	}
}
