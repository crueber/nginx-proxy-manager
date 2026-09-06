import * as api from "./base";
import type { OidcProvider } from "./models";

export async function createOidcProvider(item: OidcProvider): Promise<OidcProvider> {
	return await api.post({
		url: "/nginx/oidc-providers",
		data: item,
	});
}
