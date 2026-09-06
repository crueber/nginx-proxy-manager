import { useQuery } from "@tanstack/react-query";
import { getOidcProviders, type OidcProvider } from "src/api/backend";

const fetchOidcProviders = () => {
	return getOidcProviders();
};

const useOidcProviders = (options = {}) => {
	return useQuery<OidcProvider[], Error>({
		queryKey: ["oidc-providers"],
		queryFn: () => fetchOidcProviders(),
		staleTime: 60 * 1000,
		...options,
	});
};

export { fetchOidcProviders, useOidcProviders };
