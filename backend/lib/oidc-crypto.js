import crypto from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;

// Cached fallback key (see getKey). Module-scope on purpose: the fallback
// inputs are static, so re-deriving per encrypt/decrypt only blocks the
// event loop during bulk operations.
let cachedFallbackKey = null;

/**
 * Encryption helper for OIDC provider client secrets (at rest).
 *
 * The key is read from `NPM_OIDC_SECRET_KEY` (a 32-byte hex string) when set,
 * so deployments can use a stable, backed-up key. Otherwise a static built-in
 * fallback key is used: it is IDENTICAL on every install, so anyone holding a
 * database dump plus this source code can decrypt all secrets. Never rely on
 * the fallback in production — set `NPM_OIDC_SECRET_KEY`. Rows already
 * encrypted with the fallback key stay readable so upgrades don't brick them.
 *
 * Payload format: `v1:<iv-hex>:<auth-tag-hex>:<ciphertext-hex>`
 *
 * Secrets are write-only through the API (never serialized in GET responses)
 * and never written to logs.
 */
const getKey = () => {
	const fromEnv = process.env.NPM_OIDC_SECRET_KEY;
	if (fromEnv) {
		const buf = Buffer.from(fromEnv, "hex");
		if (buf.length === 32) {
			return buf;
		}
		throw new Error("NPM_OIDC_SECRET_KEY must be a 32-byte hex string (64 hex chars)");
	}
	// Clearly-marked fallback: static built-in key, identical everywhere.
	// NOT suitable for production. Set NPM_OIDC_SECRET_KEY instead.
	// Memoized so bulk config regeneration doesn't re-run scrypt per secret.
	if (!cachedFallbackKey) {
		cachedFallbackKey = crypto.scryptSync("npm-oidc-fallback-key", "npm-oidc-salt", 32);
	}
	return cachedFallbackKey;
};

const usingFallbackKey = () => {
	return !process.env.NPM_OIDC_SECRET_KEY;
};

const encryptSecret = (plaintext) => {
	if (typeof plaintext !== "string" || !plaintext.length) {
		return null;
	}
	const key = getKey();
	const iv = crypto.randomBytes(IV_LENGTH);
	const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
	const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
	const tag = cipher.getAuthTag();
	return `v1:${iv.toString("hex")}:${tag.toString("hex")}:${ciphertext.toString("hex")}`;
};

const decryptSecret = (payload) => {
	if (typeof payload !== "string" || !payload.length) {
		return null;
	}
	const parts = payload.split(":");
	if (parts.length !== 4 || parts[0] !== "v1") {
		throw new Error("Unknown OIDC secret payload format");
	}
	const key = getKey();
	const iv = Buffer.from(parts[1], "hex");
	const tag = Buffer.from(parts[2], "hex");
	const ciphertext = Buffer.from(parts[3], "hex");
	const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
	decipher.setAuthTag(tag);
	return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
};

export { encryptSecret, decryptSecret, usingFallbackKey };
