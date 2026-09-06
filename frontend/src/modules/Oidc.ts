import type { AccessList, OidcProvider } from "src/api/backend/models";

export const OIDC_DEFAULT_SCOPES = "openid email profile";
export const OIDC_DEFAULT_USERNAME_CLAIM = "email";

const CLAIM_NAME_RE = /^[A-Za-z0-9_.-]+$/;

export function isHttpsUrl(value: unknown): boolean {
	if (typeof value !== "string" || value.trim().length === 0) {
		return false;
	}
	try {
		return new URL(value.trim()).protocol === "https:";
	} catch {
		return false;
	}
}

/**
 * Client-side validation for the OIDC provider form. Mirrors the backend
 * rules in backend/lib/oidc.js. Returns an error key/message or null.
 */
export function validateOidcProvider(values: Partial<OidcProvider>): string | null {
	if (!values.name?.trim()) {
		return "Name is required";
	}
	if (!isHttpsUrl(values.discoveryUrl)) {
		return "Discovery URL must be a valid https:// URL";
	}
	if (!values.clientId?.trim()) {
		return "Client ID is required";
	}
	const scopes = values.scopes?.trim() || OIDC_DEFAULT_SCOPES;
	if (!scopes.split(/\s+/).includes("openid")) {
		return "Scopes must include 'openid'";
	}
	if (values.usernameClaim?.trim() && !CLAIM_NAME_RE.test(values.usernameClaim.trim())) {
		return "Username claim must be a valid claim name";
	}
	if (values.groupsClaim?.trim() && !CLAIM_NAME_RE.test(values.groupsClaim.trim())) {
		return "Groups claim must be a valid claim name";
	}
	return null;
}

/**
 * Builds the access-list association payload from attached providers.
 */
export function toOidcProviderIds(providers: OidcProvider[] | undefined): number[] {
	return [...new Set((providers || []).map((p) => p.id).filter((id): id is number => !!id && id > 0))];
}

/**
 * Resolves the initially-attached providers for the Access List form from
 * the expanded `oidcProviders` relation (falls back to explicit ids).
 */
export function initialOidcProviders(list: Partial<AccessList> | undefined): OidcProvider[] {
	return list?.oidcProviders || [];
}
