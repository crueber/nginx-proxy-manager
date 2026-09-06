import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
	fetchDiscoveryDocument,
	hydrateForNginx,
	normalizeProviderIds,
	redactSecretsForLog,
	sanitizeForApi,
	serializeProvider,
	validateProviderInput,
} from "../lib/oidc.js";
import { decryptSecret, encryptSecret, usingFallbackKey } from "../lib/oidc-crypto.js";
import utils from "../lib/utils.js";

// Fixed test key so encryption round-trips are deterministic within this run.
// oidc-crypto reads the env lazily on every call, so setting it here is enough.
process.env.NPM_OIDC_SECRET_KEY = "a".repeat(64);

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const backendDir = join(__dirname, "..");
const repoRoot = join(backendDir, "..");

const makeProviderRow = (overrides = {}) => ({
	id: 7,
	created_on: "2026-09-06T00:00:00.000Z",
	modified_on: "2026-09-06T00:00:00.000Z",
	owner_user_id: 1,
	name: "Keycloak",
	discovery_url: "https://auth.example.com/realms/npm",
	client_id: "npm",
	client_secret_encrypted: encryptSecret("super-secret-value"),
	scopes: "openid email profile",
	username_claim: "email",
	groups_claim: null,
	is_deleted: 0,
	meta: {},
	...overrides,
});

const basicOnlyList = () => ({
	id: 1,
	name: "basic",
	satisfy_any: true,
	pass_auth: false,
	items: [{ username: "admin", password: "" }],
	clients: [],
});

describe("oidc-crypto", () => {
	it("round-trips a secret", () => {
		const enc = encryptSecret("super-secret-value");
		assert.match(enc, /^v1:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/);
		assert.equal(decryptSecret(enc), "super-secret-value");
	});

	it("produces different ciphertexts for the same secret (random IV)", () => {
		assert.notEqual(encryptSecret("x"), encryptSecret("x"));
	});

	it("returns null for empty input and decrypts null as null", () => {
		assert.equal(encryptSecret(""), null);
		assert.equal(decryptSecret(null), null);
	});

	it("rejects tampered payloads", () => {
		const enc = encryptSecret("shh");
		const parts = enc.split(":");
		parts[3] = `ff${parts[3].slice(2)}`;
		assert.throws(() => decryptSecret(parts.join(":")), Error);
		assert.throws(() => decryptSecret("bogus"), Error);
	});

	it("reports key source correctly", () => {
		assert.equal(usingFallbackKey(), false);
		delete process.env.NPM_OIDC_SECRET_KEY;
		assert.equal(usingFallbackKey(), true);
		process.env.NPM_OIDC_SECRET_KEY = "a".repeat(64);
	});
});

describe("validateProviderInput", () => {
	const valid = {
		name: "Keycloak",
		discovery_url: "https://auth.example.com/realms/npm",
		client_id: "npm",
		scopes: "openid email profile",
		username_claim: "email",
	};

	it("accepts a valid generic provider", () => {
		validateProviderInput(valid, false);
	});

	it("accepts a full discovery URL too", () => {
		validateProviderInput({ ...valid, discovery_url: "https://auth.example.com/.well-known/openid-configuration" }, false);
	});

	it("rejects missing/blank required fields on create", () => {
		assert.throws(() => validateProviderInput({ ...valid, name: "  " }, false), /name/);
		assert.throws(() => validateProviderInput({ ...valid, client_id: "" }, false), /client ID/);
	});

	it("rejects non-https and malformed discovery URLs", () => {
		assert.throws(() => validateProviderInput({ ...valid, discovery_url: "http://auth.example.com/x" }, false), /https/);
		assert.throws(() => validateProviderInput({ ...valid, discovery_url: "not-a-url" }, false), /https/);
	});

	it("rejects scopes without openid", () => {
		assert.throws(() => validateProviderInput({ ...valid, scopes: "email profile" }, false), /openid/);
		assert.throws(() => validateProviderInput({ ...valid, scopes: "" }, false), /scopes/);
	});

	it("rejects template-unsafe claim names", () => {
		assert.throws(() => validateProviderInput({ ...valid, username_claim: '{{ evil }}"' }, false), /claim/);
		assert.throws(() => validateProviderInput({ ...valid, groups_claim: "a b" }, false), /claim/);
	});

	it("allows partial payloads on update", () => {
		validateProviderInput({ name: "Renamed" }, true);
		validateProviderInput({ scopes: "openid groups" }, true);
		assert.throws(() => validateProviderInput({ discovery_url: "http://x" }, true), /https/);
	});

	it("never leaks secrets in messages", () => {
		try {
			validateProviderInput({ ...valid, name: "", client_secret: "TOPSECRET" }, false);
			assert.fail("should have thrown");
		} catch (err) {
			assert.doesNotMatch(err.message, /TOPSECRET/);
		}
	});
});

describe("normalizeProviderIds", () => {
	it("dedups, parses and filters ids", () => {
		assert.deepEqual(normalizeProviderIds(["2", 2, "abc", "2abc", 2.5, -1, 0, 3]), [2, 3]);
		assert.deepEqual(normalizeProviderIds(undefined), []);
		assert.deepEqual(normalizeProviderIds([]), []);
	});
});

describe("serialize/sanitize (secret write-only)", () => {
	it("serialize strips the encrypted secret and reports has_secret", () => {
		const s = serializeProvider(makeProviderRow());
		assert.equal("client_secret_encrypted" in s, false);
		assert.equal("client_secret" in s, false);
		assert.equal(s.has_secret, true);
		assert.equal(s.name, "Keycloak");

		const noSecret = serializeProvider(makeProviderRow({ client_secret_encrypted: null }));
		assert.equal(noSecret.has_secret, false);
	});

	it("sanitizeForApi strips secrets from access-list expansions", () => {
		const list = { ...basicOnlyList(), oidc_providers: [makeProviderRow()] };
		const sanitized = sanitizeForApi(list);
		const dumped = JSON.stringify(sanitized);
		assert.doesNotMatch(dumped, /super-secret-value/);
		assert.doesNotMatch(dumped, /client_secret_encrypted/);
		assert.equal(sanitized.oidc_providers[0].has_secret, true);
		// input row is not mutated
		assert.ok(list.oidc_providers[0].client_secret_encrypted);
	});

	it("sanitizeForApi is a no-op without the expansion", () => {
		const list = basicOnlyList();
		assert.equal(sanitizeForApi(list), list);
		assert.equal(sanitizeForApi(null), null);
	});
});

describe("hydrateForNginx", () => {
	it("attaches decrypted secrets and template fields without mutating input", () => {
		const row = makeProviderRow();
		const list = { ...basicOnlyList(), oidc_providers: [row] };
		const hydrated = hydrateForNginx(list);
		assert.equal(hydrated.oidc_providers[0].client_secret, "super-secret-value");
		assert.equal("client_secret_encrypted" in hydrated.oidc_providers[0], false);
		assert.equal(
			hydrated.oidc_providers[0].discovery,
			"https://auth.example.com/realms/npm/.well-known/openid-configuration",
		);
		assert.equal(hydrated.oidc_providers[0].redirect_path, "/_npm/oidc/callback/7");
		assert.ok(row.client_secret_encrypted, "input must not be mutated");
	});

	it("keeps full discovery URLs as-is", () => {
		const list = {
			oidc_providers: [makeProviderRow({ discovery_url: "https://x.example.com/.well-known/openid-configuration" })],
		};
		assert.equal(
			hydrateForNginx(list).oidc_providers[0].discovery,
			"https://x.example.com/.well-known/openid-configuration",
		);
	});

	it("is a no-op without the expansion", () => {
		const list = basicOnlyList();
		assert.equal(hydrateForNginx(list), list);
	});

	it("renders an empty secret when none is stored (public IdP client)", () => {
		const list = { oidc_providers: [makeProviderRow({ client_secret_encrypted: null })] };
		assert.equal(hydrateForNginx(list).oidc_providers[0].client_secret, "");
	});

	it("fails visibly when a stored secret cannot be decrypted", () => {
		const list = { oidc_providers: [makeProviderRow()] };
		process.env.NPM_OIDC_SECRET_KEY = "b".repeat(64);
		try {
			assert.throws(() => hydrateForNginx(list), /cannot be decrypted/);
		} finally {
			process.env.NPM_OIDC_SECRET_KEY = "a".repeat(64);
		}
		// input row is untouched by the failed hydration
		assert.ok(list.oidc_providers[0].client_secret_encrypted);
	});
});

describe("redactSecretsForLog", () => {
	it("redacts embedded client secrets", () => {
		const out = redactSecretsForLog('client_id = "npm",\nclient_secret = "super-secret-value",');
		assert.equal(out, 'client_id = "npm",\nclient_secret = "[redacted]",');
	});

	it("redacts secrets containing escaped quotes without leaking the tail", () => {
		// As rendered by the lua_string filter for secret qu"ote\backslash
		const rendered = 'client_secret = "qu\\"ote\\\\backslash",';
		const out = redactSecretsForLog(rendered);
		assert.equal(out, 'client_secret = "[redacted]",');
		assert.doesNotMatch(out, /ote|backslash/);
	});

	it("leaves other text untouched", () => {
		assert.equal(redactSecretsForLog("satisfy any;"), "satisfy any;");
	});
});

describe("fetchDiscoveryDocument", () => {
	const doc = {
		issuer: "https://auth.example.com/realms/npm",
		authorization_endpoint: "https://auth.example.com/realms/npm/protocol/openid-connect/auth",
		token_endpoint: "https://auth.example.com/realms/npm/protocol/openid-connect/token",
		jwks_uri: "https://auth.example.com/realms/npm/protocol/openid-connect/certs",
	};

	const startServer = () =>
		new Promise((resolve) => {
		const server = http.createServer((req, res) => {
				if (req.url === "/realms/npm/.well-known/openid-configuration") {
					res.writeHead(200, { "content-type": "application/json" });
					res.end(JSON.stringify(doc));
				} else {
					res.writeHead(404);
					res.end();
				}
			});
			server.listen(0, "127.0.0.1", () => resolve(server));
		});

	it("resolves the issuer URL to the well-known document", async () => {
		const server = await startServer();
		try {
			const port = server.address().port;
			const found = await fetchDiscoveryDocument(`http://127.0.0.1:${port}/realms/npm`);
			assert.equal(found.issuer, doc.issuer);
			assert.equal(found.jwks_uri, doc.jwks_uri);
		} finally {
			server.close();
		}
	});

	it("accepts the full discovery URL directly", async () => {
		const server = await startServer();
		try {
			const port = server.address().port;
			const found = await fetchDiscoveryDocument(
				`http://127.0.0.1:${port}/realms/npm/.well-known/openid-configuration`,
			);
			assert.equal(found.authorization_endpoint, doc.authorization_endpoint);
		} finally {
			server.close();
		}
	});

	it("throws ValidationError when unreachable", async () => {
		await assert.rejects(() => fetchDiscoveryDocument("http://127.0.0.1:1/unreachable"), /OIDC discovery failed/);
	});

	it("refuses oversized discovery bodies", async () => {
		const server = http.createServer((_req, res) => {
			res.writeHead(200, { "content-type": "application/json" });
			res.end(`{"issuer":"https://x.example.com","pad":"${"p".repeat(300000)}"}`);
		});
		await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
		try {
			const port = server.address().port;
			await assert.rejects(
				() => fetchDiscoveryDocument(`http://127.0.0.1:${port}/.well-known/openid-configuration`),
				/OIDC discovery failed/,
			);
		} finally {
			server.close();
		}
	});
});

describe("nginx _access.conf rendering", () => {
	const renderAccess = async (templateText, accessList, accessListId = 1) => {
		const engine = utils.getRenderEngine();
		return engine.parseAndRender(templateText, { access_list_id: accessListId, access_list: accessList });
	};

	const developTemplate = (t) => {
		try {
			return execSync("git show develop:backend/templates/_access.conf", { cwd: repoRoot, encoding: "utf8" });
		} catch {
			t.skip("develop ref unavailable (shallow clone or missing branch)");
		}
	};

	const currentTemplate = () => fs.readFileSync(join(backendDir, "templates", "_access.conf"), "utf8");

	const withProviders = (list, providers) => hydrateForNginx({ ...list, oidc_providers: providers });

	it("basic-only output is byte-identical to develop", async (t) => {
		const ctx = basicOnlyList();
		const expected = await renderAccess(developTemplate(t), ctx);
		const actual = await renderAccess(currentTemplate(), ctx);
		assert.equal(actual, expected);
		assert.match(actual, /auth_basic/);
		assert.doesNotMatch(actual, /oidc|access_by_lua/i);
	});

	it("neither (no basic, no oidc, no clients) is byte-identical to develop", async (t) => {
		const ctx = { id: 2, name: "empty", satisfy_any: false, pass_auth: false, items: [], clients: [] };
		const expected = await renderAccess(developTemplate(t), ctx);
		const actual = await renderAccess(currentTemplate(), ctx);
		assert.equal(actual, expected);
		assert.doesNotMatch(actual, /auth_basic|access_by_lua/i);
	});

	it("oidc-only renders lua without basic and without the Basic passthrough", async () => {
		const ctx = withProviders(
			{ id: 3, name: "oidc", satisfy_any: false, pass_auth: false, items: [], clients: [] },
			[makeProviderRow()],
		);
		const out = await renderAccess(currentTemplate(), ctx);
		assert.match(out, /access_by_lua_block/);
		assert.match(out, /lua-resty-openidc/);
		assert.match(out, /auth\.example\.com\/realms\/npm\/\.well-known\/openid-configuration/);
		assert.match(out, /_npm\/oidc\/callback\/7/);
		assert.doesNotMatch(out, /auth_basic_user_file/);
		// OIDC-only must NOT skip authentication for Basic headers (no auth_basic to enforce them)
		assert.doesNotMatch(out, /http_authorization/);
	});

	it("basic+oidc renders both with OR passthrough", async () => {
		const ctx = withProviders(basicOnlyList(), [makeProviderRow()]);
		const out = await renderAccess(currentTemplate(), ctx);
		assert.match(out, /auth_basic/);
		assert.match(out, /access_by_lua_block/);
		assert.match(out, /http_authorization/);
		assert.match(out, /Basic /);
		// Spoof guard: client-supplied OIDC headers are cleared on the Basic path
		assert.match(out, /clear_header\("X-OIDC-SUB"\)/);
		assert.match(out, /clear_header\("X-OIDC-USER"\)/);
	});

	it("supports multiple providers (any-of)", async () => {

		const ctx = withProviders(basicOnlyList(), [
			makeProviderRow({ id: 7, discovery_url: "https://a.example.com" }),
			makeProviderRow({ id: 8, name: "Second", discovery_url: "https://b.example.com" }),
		]);
		const out = await renderAccess(currentTemplate(), ctx);
		assert.match(out, /a\.example\.com/);
		assert.match(out, /b\.example\.com/);
		assert.match(out, /callback\/7/);
		assert.match(out, /callback\/8/);
	});

	it("keeps IP rules independent of OIDC (allowed IP does not bypass OIDC)", async () => {
		const ctx = withProviders(
			{
				id: 5,
				name: "ip+oidc",
				satisfy_any: true,
				pass_auth: false,
				items: [],
				clients: [{ address: "192.168.0.0/24", directive: "allow" }],
			},
			[makeProviderRow()],
		);
		const out = await renderAccess(currentTemplate(), ctx);
		assert.match(out, /allow 192\.168\.0\.0\/24;/);
		assert.match(out, /deny all;/);
		assert.match(out, /access_by_lua_block/);
	});

	it("escapes quotes in secrets for lua", async () => {
		const tricky = makeProviderRow({ client_secret_encrypted: encryptSecret('qu"ote\\backslash') });
		const ctx = withProviders(
			{ id: 4, name: "esc", satisfy_any: false, pass_auth: false, items: [], clients: [] },
			[tricky],
		);
		const out = await renderAccess(currentTemplate(), ctx);
		assert.match(out, /client_secret = "qu\\"ote\\\\backslash"/);
	});
});
