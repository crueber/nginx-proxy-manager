import * as api from "./base";

export async function deleteOidcProvider(id: number): Promise<boolean> {
	return await api.del({
		url: `/nginx/oidc-providers/${id}`,
	});
}
