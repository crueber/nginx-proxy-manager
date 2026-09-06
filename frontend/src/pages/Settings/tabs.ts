export type SettingsTab = "default-site" | "oidc-providers";

export const OIDC_PROVIDERS_HASH = "#oidc-providers";

/**
 * Maps a URL hash to the Settings tab it should open. The Access List modal
 * links to `/settings#oidc-providers` when no providers exist yet; anything
 * unrecognized falls back to the default tab so bad hashes never blank the page.
 */
export function settingsTabFromHash(hash: string | undefined | null): SettingsTab {
	return hash === OIDC_PROVIDERS_HASH ? "oidc-providers" : "default-site";
}

/**
 * Maps a Settings tab back to the URL hash representing it (empty string for
 * the default tab, keeping shared URLs clean).
 */
export function settingsHashForTab(tab: SettingsTab): string {
	return tab === "oidc-providers" ? OIDC_PROVIDERS_HASH : "";
}
