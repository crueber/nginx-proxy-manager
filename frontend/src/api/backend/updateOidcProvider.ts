import * as api from "./base";
import type { OidcProvider } from "./models";

export async function updateOidcProvider(item: OidcProvider): Promise<OidcProvider> {
	// Pick only writable fields: the PUT schema rejects additional properties,
	// so readonly fields from a GET object (id, timestamps, hasSecret,
	// ownerUserId, meta, expansions) must never be sent.
	const data: Record<string, any> = {
		name: item.name,
		discoveryUrl: item.discoveryUrl,
		clientId: item.clientId,
		scopes: item.scopes,
		usernameClaim: item.usernameClaim,
		groupsClaim: item.groupsClaim,
	};
	// Secret is write-only: only send when rotating.
	if (item.clientSecret) {
		data.clientSecret = item.clientSecret;
	}

	return await api.put({
		url: `/nginx/oidc-providers/${item.id}`,
		data: data,
	});
}
