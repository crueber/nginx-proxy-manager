import cn from "classnames";
import { useState } from "react";
import { T } from "src/locale";
import DefaultSite from "./DefaultSite";
import OidcProviders from "./OidcProviders";

type Tab = "default-site" | "oidc-providers";

const OIDC_HASH = "#oidc-providers";

// The Access List modal links here as `/settings#oidc-providers` when no
// providers exist yet, so honor the hash on load.
function initialTab(): Tab {
	if (typeof window !== "undefined" && window.location.hash === OIDC_HASH) {
		return "oidc-providers";
	}
	return "default-site";
}

export default function Layout() {
	// Taken from https://preview.tabler.io/settings.html
	// Refer to that when updating this content
	const [tab, setTab] = useState<Tab>(initialTab);

	const selectTab = (id: Tab) => {
		setTab(id);
		if (typeof window !== "undefined") {
			window.location.hash = id === "oidc-providers" ? OIDC_HASH : "";
		}
	};

	const navItem = (id: Tab, labelId: string) => (
		<a
			href="#"
			className={cn("list-group-item list-group-item-action d-flex align-items-center", { active: tab === id })}
			onClick={(e) => {
				e.preventDefault();
				selectTab(id);
			}}
		>
			<T id={labelId} />
		</a>
	);

	return (
		<div className="card mt-4">
			<div className="card-status-top bg-teal" />
			<div className="card-table">
				<div className="card-header">
					<div className="row w-full">
						<h2 className="mt-1 mb-0">
							<T id="settings" />
						</h2>
					</div>
				</div>
				<div className="row g-0">
					<div className="col-12 col-md-3 border-end">
						<div className="card-body mt-0 pt-0">
							<div className="list-group list-group-transparent">
								{navItem("default-site", "settings.default-site")}
								{navItem("oidc-providers", "settings.oidc-providers")}
							</div>
						</div>
					</div>
					<div className="col-12 col-md-9 d-flex flex-column">
						{tab === "default-site" ? <DefaultSite /> : <OidcProviders />}
					</div>
				</div>
			</div>
		</div>
	);
}
