import _ from "lodash";
import errs from "./error.js";
import { decryptSecret } from "./oidc-crypto.js";

const DEFAULT_SCOPES = "openid email profile";
const DEFAULT_USERNAME_CLAIM = "email";
const CLAIM_NAME_RE = /^[A-Za-z0-9_.-]+$/;

/**
 * Pure OIDC provider helpers (no database access) so they can be unit tested
 * in isolation. Database-backed CRUD lives in backend/internal/oidc-provider.js.
 *
 * Security invariants enforced here:
 * - client secrets are write-only: they are never serialized for API responses
 * - secrets are never included in error messages or logs
 */

/**
 * Validates provider input. Throws ValidationError on failure.
 * Never includes secrets in error messages.
 *
 * @param {Object} data
 * @param {Boolean} isUpdate
 */
const validateProviderInput = (data, isUpdate = false) => {
	if (!isUpdate || typeof data.name !== "undefined") {
		if (typeof data.name !== "string" || !data.name.trim().length || data.name.trim().length > 255) {
			throw new errs.ValidationError("OIDC provider name is required (1-255 chars)");
		}
	}

	if (!isUpdate || typeof data.discovery_url !== "undefined") {
		let parsed = null;
		try {
			parsed = new URL(data.discovery_url);
		} catch (_err) {
			parsed = null;
		}
		if (parsed?.protocol !== "https:") {
			throw new errs.ValidationError("OIDC discovery URL must be a valid https:// URL");
		}
	}

	if (!isUpdate || typeof data.client_id !== "undefined") {
		if (typeof data.client_id !== "string" || !data.client_id.trim().length) {
			throw new errs.ValidationError("OIDC client ID is required");
		}
	}

	if (typeof data.scopes !== "undefined" && data.scopes !== null) {
		if (typeof data.scopes !== "string" || !data.scopes.trim().length) {
			throw new errs.ValidationError("OIDC scopes must be a non-empty string");
		}
		const scopeParts = data.scopes.trim().split(/\s+/);
		if (!scopeParts.includes("openid")) {
			throw new errs.ValidationError("OIDC scopes must include 'openid'");
		}
	}

	if (typeof data.username_claim !== "undefined" && data.username_claim !== null) {
		if (
			typeof data.username_claim !== "string" ||
			!data.username_claim.trim().length ||
			!CLAIM_NAME_RE.test(data.username_claim.trim())
		) {
			throw new errs.ValidationError("OIDC username claim must be a non-empty claim name");
		}
	}

	if (typeof data.groups_claim !== "undefined" && data.groups_claim !== null && data.groups_claim !== "") {
		if (typeof data.groups_claim !== "string" || !CLAIM_NAME_RE.test(data.groups_claim.trim())) {
			throw new errs.ValidationError("OIDC groups claim must be a valid claim name");
		}
	}
};

/**
 * Fetches and validates the OIDC discovery document for an issuer URL.
 * Accepts either the issuer URL or the full discovery URL.
 * Returns the parsed discovery document. Never logs secrets.
 *
 * @param {String} discoveryUrl
 * @returns {Promise<Object>}
 */
const fetchDiscoveryDocument = async (discoveryUrl) => {
	const candidates = [discoveryUrl];
	if (!discoveryUrl.includes("/.well-known/openid-configuration")) {
		candidates.push(`${discoveryUrl.replace(/\/$/, "")}/.well-known/openid-configuration`);
	}

	let lastError = null;
	for (const url of candidates) {
		try {
			const controller = new AbortController();
			const timeout = setTimeout(() => controller.abort(), 10000);
			const res = await fetch(url, { signal: controller.signal });
			clearTimeout(timeout);
			if (!res.ok) {
				lastError = new Error(`Discovery endpoint returned HTTP ${res.status}`);
				continue;
			}
			const doc = await res.json();
			if (!doc || typeof doc !== "object" || !doc.issuer || !doc.authorization_endpoint || !doc.jwks_uri) {
				lastError = new Error("Discovery document is missing required fields (issuer, authorization_endpoint, jwks_uri)");
				continue;
			}
			return doc;
		} catch (err) {
			lastError = err;
		}
	}
	throw new errs.ValidationError(`OIDC discovery failed: ${lastError ? lastError.message : "unknown error"}`);
};

/**
 * Normalizes an access-list ↔ provider ID list (any-of semantics):
 * integer parsing, positive-only, de-duplicated. Used by
 * `setProvidersForAccessList` and unit-tested here.
 *
 * @param {Array} providerIds
 * @returns {Array<Integer>}
 */
const normalizeProviderIds = (providerIds) => {
	return [...new Set((providerIds || []).map((id) => Number.parseInt(id, 10)).filter((id) => id > 0))];
};

/**
 * Serialize a provider row for API responses.
 * The encrypted secret is NEVER included; `has_secret` signals rotation state.
 *
 * @param {Object} row
 * @returns {Object}
 */
const serializeProvider = (row) => {
	if (!row) {
		return row;
	}
	const serialized = _.omit(row, ["client_secret_encrypted"]);
	serialized.has_secret = !!row.client_secret_encrypted;
	return serialized;
};

/**
 * Decrypts a provider's client secret for nginx config generation only.
 * Must never be used in API responses or logs.
 *
 * @param {Object} row
 * @returns {String|null}
 */
const getDecryptedSecret = (row) => {
	return decryptSecret(row?.client_secret_encrypted);
};

/**
 * Prepares an access list (as loaded with the `oidc_providers` expansion)
 * for nginx config generation: attaches the decrypted `client_secret` to
 * each provider and strips the encrypted payload. The returned object is
 * a copy; the input row is not modified. Callers must ensure the result
 * is never sent to API clients or written to logs.
 *
 * @param {Object} accessList
 * @returns {Object}
 */
const hydrateForNginx = (accessList) => {
	if (!accessList || !Array.isArray(accessList.oidc_providers)) {
		return accessList;
	}
	const hydrated = { ...accessList };
	hydrated.oidc_providers = accessList.oidc_providers.map((provider) => {
		const copy = _.omit(provider, ["client_secret_encrypted"]);
		let secret = null;
		try {
			secret = getDecryptedSecret(provider);
		} catch (_err) {
			secret = null;
		}
		copy.client_secret = secret || "";
		// Normalize the discovery document URL for lua-resty-openidc, which
		// expects the full .well-known document URL (not just the issuer).
		const discoveryUrl = String(provider.discovery_url || "");
		copy.discovery = discoveryUrl.includes("/.well-known/openid-configuration")
			? discoveryUrl
			: `${discoveryUrl.replace(/\/$/, "")}/.well-known/openid-configuration`;
		// Per-provider redirect path; the scheme+host are resolved per request
		// in Lua so one list works across all proxy hosts using it.
		copy.redirect_path = `/_npm/oidc/callback/${provider.id}`;
		return copy;
	});
	return hydrated;
};

/**
 * Strips secret material from an access list carrying the `oidc_providers`
 * expansion, for safe use in API responses and audit logs.
 *
 * @param {Object} accessList
 * @returns {Object}
 */
const sanitizeForApi = (accessList) => {
	if (!accessList || !Array.isArray(accessList.oidc_providers)) {
		return accessList;
	}
	const sanitized = { ...accessList };
	sanitized.oidc_providers = accessList.oidc_providers.map((provider) =>
		serializeProvider(_.omit(provider, ["client_secret"])),
	);
	return sanitized;
};

export {
	CLAIM_NAME_RE,
	DEFAULT_SCOPES,
	DEFAULT_USERNAME_CLAIM,
	fetchDiscoveryDocument,
	getDecryptedSecret,
	hydrateForNginx,
	normalizeProviderIds,
	sanitizeForApi,
	serializeProvider,
	validateProviderInput,
};
