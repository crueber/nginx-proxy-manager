import { migrate as logger } from "../logger.js";

const migrateName = "oidc_providers";

/**
 * Migrate
 *
 * OIDC providers are global/reusable and attach to access lists
 * via the access_list_oidc join table (any-of semantics).
 *
 * @see http://knexjs.org/#Schema
 *
 * @param   {Object}  knex
 * @returns {Promise}
 */
const up = (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);

	return knex.schema
		.createTable("oidc_provider", (table) => {
			table.increments().primary();
			table.dateTime("created_on").notNull();
			table.dateTime("modified_on").notNull();
			table.integer("owner_user_id").notNull().unsigned();
			table.string("name").notNull().unique();
			table.string("discovery_url").notNull();
			table.string("client_id").notNull();
			// AES-256-GCM encrypted client secret (see backend/lib/oidc-crypto.js).
			// Never serialized via the API; write-only with re-entry to rotate.
			table.text("client_secret_encrypted").nullable();
			table.string("scopes").notNull().defaultTo("openid email profile");
			table.string("username_claim").notNull().defaultTo("email");
			table.string("groups_claim").nullable();
			table.integer("is_deleted").notNull().defaultTo(0);
			table.json("meta").notNull();
		})
		.then(() => {
			logger.info(`[${migrateName}] oidc_provider Table created`);

			return knex.schema.createTable("access_list_oidc", (table) => {
				table.increments().primary();
				table.dateTime("created_on").notNull();
				table.dateTime("modified_on").notNull();
				table.integer("access_list_id").notNull().unsigned();
				table.integer("oidc_provider_id").notNull().unsigned();
				table.unique(["access_list_id", "oidc_provider_id"]);
				table.index(["oidc_provider_id"]);
			});
		})
		.then(() => {
			logger.info(`[${migrateName}] access_list_oidc Table created`);
		});
};

/**
 * Undo Migrate
 *
 * @param {Object} knex
 * @returns {Promise}
 */
const down = (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);

	return knex.schema
		.dropTable("access_list_oidc")
		.then(() => {
			logger.info(`[${migrateName}] access_list_oidc Table dropped`);
			return knex.schema.dropTable("oidc_provider");
		})
		.then(() => {
			logger.info(`[${migrateName}] oidc_provider Table dropped`);
		});
};

export { up, down };
