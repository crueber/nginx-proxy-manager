import { describe, expect, it } from "vitest";
import {
	initialOidcProviders,
	isHttpsUrl,
	OIDC_DEFAULT_SCOPES,
	toOidcProviderIds,
	validateOidcProvider,
} from "./Oidc";

describe("isHttpsUrl", () => {
	it("accepts https issuer and discovery urls", () => {
		expect(isHttpsUrl("https://auth.example.com/realms/npm")).toBe(true);
		expect(isHttpsUrl("https://auth.example.com/.well-known/openid-configuration")).toBe(true);
	});

	it("rejects http, garbage and empty values", () => {
		expect(isHttpsUrl("http://auth.example.com/x")).toBe(false);
		expect(isHttpsUrl("not-a-url")).toBe(false);
		expect(isHttpsUrl("")).toBe(false);
		expect(isHttpsUrl(undefined)).toBe(false);
	});
});

describe("validateOidcProvider", () => {
	const valid = {
		name: "Keycloak",
		discoveryUrl: "https://auth.example.com/realms/npm",
		clientId: "npm",
		scopes: OIDC_DEFAULT_SCOPES,
		usernameClaim: "email",
	};

	it("accepts a valid generic provider", () => {
		expect(validateOidcProvider(valid)).toBeNull();
	});

	it("rejects missing name, bad discovery url and missing client id", () => {
		expect(validateOidcProvider({ ...valid, name: "  " })).not.toBeNull();
		expect(validateOidcProvider({ ...valid, discoveryUrl: "http://x" })).not.toBeNull();
		expect(validateOidcProvider({ ...valid, clientId: "" })).not.toBeNull();
	});

	it("rejects scopes without openid and unsafe claim names", () => {
		expect(validateOidcProvider({ ...valid, scopes: "email profile" })).not.toBeNull();
		expect(validateOidcProvider({ ...valid, usernameClaim: '{{ x }}"' })).not.toBeNull();
		expect(validateOidcProvider({ ...valid, groupsClaim: "a b" })).not.toBeNull();
	});

	it("allows empty optional claims", () => {
		expect(validateOidcProvider({ ...valid, groupsClaim: "" })).toBeNull();
	});
});

describe("toOidcProviderIds", () => {
	it("extracts unique positive ids", () => {
		expect(toOidcProviderIds([{ id: 2 } as any, { id: 2 } as any, { id: -1 } as any, {} as any])).toEqual([2]);
		expect(toOidcProviderIds(undefined)).toEqual([]);
	});
});

describe("initialOidcProviders", () => {
	it("falls back to an empty list", () => {
		expect(initialOidcProviders(undefined)).toEqual([]);
		expect(initialOidcProviders({} as any)).toEqual([]);
	});
});
