import * as api from "./base";
import type { OidcProvider } from "./models";

export async function updateOidcProvider(item: OidcProvider): Promise<OidcProvider> {
	// Remove readonly fields
	const { id, createdOn: _, modifiedOn: __, hasSecret: ___, ...data } = item;

	return await api.put({
		url: `/nginx/oidc-providers/${id}`,
		data: data,
	});
}
