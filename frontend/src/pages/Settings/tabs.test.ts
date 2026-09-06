import { describe, expect, it } from "vitest";
import { OIDC_PROVIDERS_HASH, settingsHashForTab, settingsTabFromHash } from "./tabs";

describe("settingsTabFromHash", () => {
	it("opens the OIDC tab for #oidc-providers", () => {
		expect(settingsTabFromHash("#oidc-providers")).toBe("oidc-providers");
	});

	it("falls back to the default tab for anything else", () => {
		expect(settingsTabFromHash("")).toBe("default-site");
		expect(settingsTabFromHash("#default-site")).toBe("default-site");
		expect(settingsTabFromHash("#bogus")).toBe("default-site");
		expect(settingsTabFromHash(undefined)).toBe("default-site");
		expect(settingsTabFromHash(null)).toBe("default-site");
	});
});

describe("settingsHashForTab", () => {
	it("round-trips both tabs", () => {
		expect(settingsTabFromHash(settingsHashForTab("oidc-providers"))).toBe("oidc-providers");
		expect(settingsTabFromHash(settingsHashForTab("default-site"))).toBe("default-site");
		expect(settingsHashForTab("oidc-providers")).toBe(OIDC_PROVIDERS_HASH);
		expect(settingsHashForTab("default-site")).toBe("");
	});
});
