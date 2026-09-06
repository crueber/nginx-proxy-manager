import express from "express";
import internalOidcProvider from "../../internal/oidc-provider.js";
import jwtdecode from "../../lib/express/jwt-decode.js";
import apiValidator from "../../lib/validator/api.js";
import validator from "../../lib/validator/index.js";
import { debug, express as logger } from "../../logger.js";
import { getValidationSchema } from "../../schema/index.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

/**
 * /api/nginx/oidc-providers
 */
router
	.route("/")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())

	/**
	 * GET /api/nginx/oidc-providers
	 *
	 * Retrieve all OIDC providers (secrets never serialized)
	 */
	.get(async (req, res, next) => {
		try {
			const data = await validator(
				{
					additionalProperties: false,
					properties: {
						query: {
							$ref: "common#/properties/query",
						},
					},
				},
				{
					query: typeof req.query.query === "string" ? req.query.query : null,
				},
			);
			const rows = await internalOidcProvider.getAll(res.locals.access, data.query);
			res.status(200).send(rows);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})

	/**
	 * POST /api/nginx/oidc-providers
	 *
	 * Create a new OIDC provider (secret write-only, encrypted at rest)
	 */
	.post(async (req, res, next) => {
		try {
			const payload = await apiValidator(getValidationSchema("/nginx/oidc-providers", "post"), req.body);
			const result = await internalOidcProvider.create(res.locals.access, payload);
			res.status(201).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * Specific OIDC provider
 *
 * /api/nginx/oidc-providers/123
 */
router
	.route("/:provider_id")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())

	/**
	 * GET /api/nginx/oidc-providers/123
	 *
	 * Retrieve a specific OIDC provider (secrets never serialized)
	 */
	.get(async (req, res, next) => {
		try {
			const data = await validator(
				{
					required: ["provider_id"],
					additionalProperties: false,
					properties: {
						provider_id: {
							$ref: "common#/properties/id",
						},
					},
				},
				{
					provider_id: req.params.provider_id,
				},
			);
			const row = await internalOidcProvider.get(res.locals.access, {
				id: Number.parseInt(data.provider_id, 10),
			});
			res.status(200).send(row);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})

	/**
	 * PUT /api/nginx/oidc-providers/123
	 *
	 * Update an existing OIDC provider (secret re-entry rotates, never returned)
	 */
	.put(async (req, res, next) => {
		try {
			const payload = await apiValidator(getValidationSchema("/nginx/oidc-providers/{providerID}", "put"), req.body);
			payload.id = Number.parseInt(req.params.provider_id, 10);
			const result = await internalOidcProvider.update(res.locals.access, payload);
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})

	/**
	 * DELETE /api/nginx/oidc-providers/123
	 *
	 * Delete an existing OIDC provider (also detaches it from all access lists)
	 */
	.delete(async (req, res, next) => {
		try {
			const result = await internalOidcProvider.delete(res.locals.access, {
				id: Number.parseInt(req.params.provider_id, 10),
			});
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * Test/validate a provider against its discovery endpoint
 *
 * POST /api/nginx/oidc-providers/123/test
 */
router
	.route("/:provider_id/test")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.post(async (req, res, next) => {
		try {
			const data = await validator(
				{
					required: ["provider_id"],
					additionalProperties: false,
					properties: {
						provider_id: {
							$ref: "common#/properties/id",
						},
					},
				},
				{
					provider_id: req.params.provider_id,
				},
			);
			const result = await internalOidcProvider.test(res.locals.access, {
				id: Number.parseInt(data.provider_id, 10),
			});
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

export default router;
