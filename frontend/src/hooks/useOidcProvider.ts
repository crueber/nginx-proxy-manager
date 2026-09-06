import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
	createOidcProvider,
	getOidcProvider,
	type OidcProvider,
	updateOidcProvider,
} from "src/api/backend";

const fetchOidcProvider = (id: number | "new") => {
	if (id === "new") {
		return Promise.resolve({
			name: "",
			discoveryUrl: "",
			clientId: "",
			clientSecret: "",
			scopes: "openid email profile",
			usernameClaim: "email",
			groupsClaim: "",
		} as OidcProvider);
	}
	return getOidcProvider(id);
};

const useOidcProvider = (id: number | "new", options = {}) => {
	return useQuery<OidcProvider, Error>({
		queryKey: ["oidc-provider", id],
		queryFn: () => fetchOidcProvider(id),
		staleTime: 60 * 1000, // 1 minute
		...options,
	});
};

const useSetOidcProvider = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: (values: OidcProvider) =>
			values.id ? updateOidcProvider(values) : createOidcProvider(values),
		onSuccess: async ({ id }: OidcProvider) => {
			queryClient.invalidateQueries({ queryKey: ["oidc-provider", id] });
			queryClient.invalidateQueries({ queryKey: ["oidc-providers"] });
			queryClient.invalidateQueries({ queryKey: ["access-lists"] });
			queryClient.invalidateQueries({ queryKey: ["audit-logs"] });
		},
	});
};

export { useOidcProvider, useSetOidcProvider };
