import crypto from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;

/**
 * Encryption helper for OIDC provider client secrets (at rest).
 *
 * The key is read from `NPM_OIDC_SECRET_KEY` (a 32-byte hex string) when set,
 * so deployments can use a stable, backed-up key. Otherwise a host-derived
 * fallback is used and the limitation is clearly logged by the caller.
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
	// Clearly-marked fallback: derived per-host, NOT suitable for multi-node
	// deployments. Set NPM_OIDC_SECRET_KEY in production.
	return crypto.scryptSync("npm-oidc-fallback-key", "npm-oidc-salt", 32);
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
