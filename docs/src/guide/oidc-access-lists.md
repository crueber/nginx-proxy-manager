# OIDC Authentication for Access Lists

Access Lists can protect a Proxy Host with generic OpenID Connect (OIDC) in addition to
(or instead of) HTTP Basic Auth. Any standards-compliant provider works via OIDC discovery
(Keycloak, Authentik, Authelia, Auth0, Google, …).

## Configure providers (Settings → OIDC Providers)

Each provider needs:

- **Name** — display label, must be unique.
- **Discovery / Issuer URL** — e.g. `https://auth.example.com/realms/npm` (must be `https://`).
- **Client ID** and **Client Secret** — create these in your IdP first.
- **Scopes** — default `openid email profile` (must include `openid`).
- **Username claim** — default `email`; used for the `X-OIDC-USER` upstream header.
- **Groups claim** — optional, reserved for future group-based rules.

The **Test** button hits the provider's discovery endpoint
(`/.well-known/openid-configuration`) and reports the issuer, authorization endpoint
and JWKS URI. The client secret is stored encrypted in the database, is write-only
through the API (leave the field blank to keep the stored secret), and is never
returned by the API or written to logs.

Set `NPM_OIDC_SECRET_KEY` to a 32-byte hex string so the encryption key is stable
and backed up. Without it, a host-derived fallback key is used (single-node only).

## Attach providers to an Access List

Edit an Access List and open the **OIDC Providers** tab (shown only when at least
one provider exists; otherwise the Authorizations tab links to Settings). Attach one
or more providers, which are tried in order with first success winning.

By design there is no per-provider login chooser: an unauthenticated request is
redirected by the **first** attached provider (redirect-and-exit), so the initial
login always goes through it; later providers serve as fallback for flows where
authentication returns instead of redirecting. A provider either redirects back
with credentials (access granted) or the chain continues on failure; if every
attached provider fails, the request gets a 401.

Enforcement semantics:

- **Basic users + OIDC providers**: either method passing grants access (OR).
  OIDC never silently disables Basic Auth.
- **OIDC only**: OIDC alone is required.
- **Neither**: existing behavior (allow/IP rules only) is unchanged.

IP allow/deny rules (`clients`) are orthogonal: an allowed IP does **not** bypass
OIDC (fail-closed AND). Only Basic Auth participates in OR semantics with OIDC.

## Runtime requirements

Enforcement is rendered as an `access_by_lua_block` using `lua-resty-openidc`, so
Proxy Hosts using OIDC attachment require an **OpenResty** runtime. Tokens are
verified against the provider JWKS fetched via the discovery document; `state` and
`nonce` are validated by `lua-resty-openidc`.

Redirect URIs are derived per request as
`<scheme>://<host>/_npm/oidc/callback/<provider-id>` — register one such URI per
Proxy Host domain in your IdP client. Authenticated requests reach upstream with
`X-OIDC-SUB` and `X-OIDC-USER` headers.

## Manual test checklist

1. Add a provider in Settings, press **Test**, expect the issuer summary.
2. Create an Access List with one Basic user, attach the provider, assign it to a
   Proxy Host.
3. With `Authorization: Basic …` credentials → proxied (Basic path).
4. Without credentials → redirected to the IdP login (OIDC path).
5. Remove all Basic users → OIDC alone is required.
6. Remove all OIDC attachments → output identical to a Basic-only list
   (covered by automated template tests for all 4 combos).
