import * as api from "./base";

export interface OidcProviderTestResult {
	ok: boolean;
	issuer: string;
	authorizationEndpoint: string;
	jwksUri: string;
}

export async function testOidcProvider(id: number): Promise<OidcProviderTestResult> {
	return await api.post({
		url: `/nginx/oidc-providers/${id}/test`,
	});
}
