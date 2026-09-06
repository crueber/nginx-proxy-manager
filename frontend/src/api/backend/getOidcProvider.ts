import * as api from "./base";
import type { OidcProvider } from "./models";

export async function getOidcProvider(id: number): Promise<OidcProvider> {
	return await api.get({
		url: `/nginx/oidc-providers/${id}`,
	});
}
