import * as api from "./base";
import type { OidcProvider } from "./models";

export async function getOidcProviders(params = {}): Promise<OidcProvider[]> {
	return await api.get({
		url: "/nginx/oidc-providers",
		params,
	});
}
