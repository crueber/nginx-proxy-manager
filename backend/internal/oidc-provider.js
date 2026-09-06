import _ from "lodash";
import errs from "../lib/error.js";
import {
	DEFAULT_SCOPES,
	DEFAULT_USERNAME_CLAIM,
	fetchDiscoveryDocument,
	getDecryptedSecret,
	hydrateForNginx,
	normalizeProviderIds,
	sanitizeForApi,
	serializeProvider,
	validateProviderInput,
} from "../lib/oidc.js";
import { encryptSecret, usingFallbackKey } from "../lib/oidc-crypto.js";
import utils from "../lib/utils.js";
import { access as logger } from "../logger.js";
import accessListOidcModel from "../models/access_list_oidc.js";
import oidcProviderModel from "../models/oidc_provider.js";
import internalAuditLog from "./audit-log.js";

const omissions = () => {
	return ["is_deleted", "client_secret_encrypted"];
};

const internalOidcProvider = {
	DEFAULT_SCOPES,
	DEFAULT_USERNAME_CLAIM,

	serialize: serializeProvider,
	getDecryptedSecret,
	hydrateForNginx,
	sanitizeForApi,

	/**
	 * @param {Access} access
	 * @param {String} [searchQuery]
	 * @returns {Promise}
	 */
	getAll: async (access, searchQuery) => {
		const accessData = await access.can("access_lists:list");

		const query = oidcProviderModel.query().where("oidc_provider.is_deleted", 0).orderBy("oidc_provider.name", "ASC");

		if (accessData.permission_visibility !== "all") {
			query.andWhere("oidc_provider.owner_user_id", access.token.getUserId(1));
		}

		if (typeof searchQuery === "string") {
			const escaped = searchQuery.replace(/[\\%_]/g, (c) => `\\${c}`);
			query.where("oidc_provider.name", "like", `%${escaped}%`);
		}

		const rows = await query.then(utils.omitRows(omissions()));
		return rows.map((row) => internalOidcProvider.serialize(row));
	},

	/**
	 * @param {Access} access
	 * @param {Object} data
	 * @param {Integer} data.id
	 * @returns {Promise}
	 */
	get: async (access, data) => {
		const accessData = await access.can("access_lists:get", data.id);

		const query = oidcProviderModel.query().where("oidc_provider.is_deleted", 0).andWhere("oidc_provider.id", data.id).first();

		if (accessData.permission_visibility !== "all") {
			query.andWhere("oidc_provider.owner_user_id", access.token.getUserId(1));
		}

		const row = await query.then(utils.omitRow(omissions()));
		if (!row?.id) {
			throw new errs.ItemNotFoundError(data.id);
		}
		return internalOidcProvider.serialize(row);
	},

	/**
	 * @param {Access} access
	 * @param {Object} data
	 * @returns {Promise}
	 */
	create: async (access, data) => {
		await access.can("access_lists:create", data);
		validateProviderInput(data, false);

		const existing = await oidcProviderModel.query().where("name", data.name.trim()).andWhere("is_deleted", 0).first();
		if (existing) {
			throw new errs.ValidationError("An OIDC provider with this name already exists");
		}

		if (usingFallbackKey()) {
			logger.warn(
				"NPM_OIDC_SECRET_KEY is not set; using static built-in fallback key for OIDC secret encryption. Set NPM_OIDC_SECRET_KEY in production",
			);
		}

		const row = await oidcProviderModel
			.query()
			.insertAndFetch({
				name: data.name.trim(),
				discovery_url: data.discovery_url.trim(),
				client_id: data.client_id.trim(),
				client_secret_encrypted: data.client_secret ? encryptSecret(data.client_secret) : null,
				scopes: data.scopes?.trim() || DEFAULT_SCOPES,
				username_claim: data.username_claim?.trim() || DEFAULT_USERNAME_CLAIM,
				groups_claim: data.groups_claim?.trim() || null,
				owner_user_id: access.token.getUserId(1),
			})
			.then(utils.omitRow(omissions()));

		await internalAuditLog.add(access, {
			action: "created",
			object_type: "oidc-provider",
			object_id: row.id,
			meta: internalOidcProvider.serialize(row),
		});

		return internalOidcProvider.serialize(row);
	},

	/**
	 * @param {Access} access
	 * @param {Object} data
	 * @returns {Promise}
	 */
	update: async (access, data) => {
		const accessData = await access.can("access_lists:update", data.id);
		validateProviderInput(data, true);

		const query = oidcProviderModel.query().where("id", data.id).andWhere("is_deleted", 0);
		if (accessData.permission_visibility !== "all") {
			query.andWhere("owner_user_id", access.token.getUserId(1));
		}
		const row = await query.first();
		if (!row?.id) {
			throw new errs.ItemNotFoundError(data.id);
		}

		if (typeof data.name !== "undefined" && data.name.trim() !== row.name) {
			const existing = await oidcProviderModel
				.query()
				.where("name", data.name.trim())
				.andWhere("is_deleted", 0)
				.whereNot("id", data.id)
				.first();
			if (existing) {
				throw new errs.ValidationError("An OIDC provider with this name already exists");
			}
		}

		const patch = {};
		if (typeof data.name !== "undefined") {
			patch.name = data.name.trim();
		}
		if (typeof data.discovery_url !== "undefined") {
			patch.discovery_url = data.discovery_url.trim();
		}
		if (typeof data.client_id !== "undefined") {
			patch.client_id = data.client_id.trim();
		}
		// Secret is write-only: only overwrite when a new non-empty value is supplied (rotate).
		if (typeof data.client_secret !== "undefined" && data.client_secret) {
			if (usingFallbackKey()) {
				logger.warn(
				"NPM_OIDC_SECRET_KEY is not set; using static built-in fallback key for OIDC secret encryption. Set NPM_OIDC_SECRET_KEY in production",
			);
			}
			patch.client_secret_encrypted = encryptSecret(data.client_secret);
		}
		if (typeof data.scopes !== "undefined") {
			patch.scopes = data.scopes?.trim() || DEFAULT_SCOPES;
		}
		if (typeof data.username_claim !== "undefined") {
			patch.username_claim = data.username_claim?.trim() || DEFAULT_USERNAME_CLAIM;
		}
		if (typeof data.groups_claim !== "undefined") {
			patch.groups_claim = data.groups_claim?.trim() || null;
		}

		if (Object.keys(patch).length) {
			await oidcProviderModel.query().where("id", data.id).patch(patch);
		}

		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "oidc-provider",
			object_id: data.id,
			meta: _.omit(data, ["client_secret"]),
		});

		return internalOidcProvider.get(access, { id: data.id });
	},

	/**
	 * @param {Access} access
	 * @param {Object} data
	 * @param {Integer} data.id
	 * @returns {Promise}
	 */
	delete: async (access, data) => {
		const accessData = await access.can("access_lists:delete", data.id);
		const query = oidcProviderModel.query().where("id", data.id).andWhere("is_deleted", 0);
		if (accessData.permission_visibility !== "all") {
			query.andWhere("owner_user_id", access.token.getUserId(1));
		}
		const row = await query.first();
		if (!row?.id) {
			throw new errs.ItemNotFoundError(data.id);
		}

		await oidcProviderModel.query().where("id", data.id).patch({ is_deleted: 1 });
		// Detach from all access lists
		await accessListOidcModel.query().delete().where("oidc_provider_id", data.id);

		await internalAuditLog.add(access, {
			action: "deleted",
			object_type: "oidc-provider",
			object_id: data.id,
			meta: { name: row.name },
		});
		return true;
	},

	/**
	 * Hits the provider's discovery endpoint and reports issuer + endpoint summary.
	 * Never returns or logs secrets.
	 *
	 * @param {Access} access
	 * @param {Object} data
	 * @param {Integer} data.id
	 * @returns {Promise<Object>}
	 */
	test: async (access, data) => {
		const accessData = await access.can("access_lists:get", data.id);
		const query = oidcProviderModel.query().where("id", data.id).andWhere("is_deleted", 0);
		if (accessData.permission_visibility !== "all") {
			query.andWhere("owner_user_id", access.token.getUserId(1));
		}
		const row = await query.first();
		if (!row?.id) {
			throw new errs.ItemNotFoundError(data.id);
		}
		const doc = await fetchDiscoveryDocument(row.discovery_url);
		return {
			ok: true,
			issuer: doc.issuer,
			authorization_endpoint: doc.authorization_endpoint,
			jwks_uri: doc.jwks_uri,
		};
	},

	/**
	 * Validates association candidate IDs and returns the normalized list.
	 * Unknown, deleted — or, for restricted-visibility users, unowned —
	 * provider IDs are rejected without revealing which (same error).
	 *
	 * @param {Array} providerIds
	 * @param {Object} [scope]
	 * @param {Integer} [scope.ownerUserId]
	 * @param {String} [scope.visibility]
	 * @returns {Promise<Array<Integer>>}
	 */
	resolveProviderIds: async (providerIds, scope) => {
		const ids = normalizeProviderIds(providerIds);
		// Defense-in-depth: API schema should reject garbage, but a non-empty
		// raw list that normalizes to empty must not silently detach all
		// providers — fail loudly instead.
		if (Array.isArray(providerIds) && providerIds.length > 0 && ids.length === 0) {
			throw new errs.ValidationError("One or more OIDC providers do not exist");
		}
		if (ids.length) {
			const query = oidcProviderModel.query().whereIn("id", ids).andWhere("is_deleted", 0);
			if (scope && scope.visibility !== "all") {
				query.andWhere("owner_user_id", scope.ownerUserId);
			}
			const rows = await query;
			if (rows.length !== ids.length) {
				throw new errs.ValidationError("One or more OIDC providers do not exist");
			}
		}
		return ids;
	},

	/**
	 * Syncs the access-list ↔ provider association (any-of semantics).
	 * The delete+insert sync runs in a transaction so a failed insert
	 * cannot leave a partially-attached list.
	 *
	 * @param {Integer} accessListId
	 * @param {Array} providerIds
	 * @param {Object} [scope]  See resolveProviderIds
	 * @returns {Promise}
	 */
	setProvidersForAccessList: async (accessListId, providerIds, scope) => {
		const ids = await internalOidcProvider.resolveProviderIds(providerIds, scope);
		await accessListOidcModel.transaction(async (trx) => {
			await accessListOidcModel.query(trx).delete().where("access_list_id", accessListId);
			for (const providerId of ids) {
				await accessListOidcModel.query(trx).insert({
					access_list_id: accessListId,
					oidc_provider_id: providerId,
				});
			}
		});
	},
};

export { fetchDiscoveryDocument, validateProviderInput };
export default internalOidcProvider;
