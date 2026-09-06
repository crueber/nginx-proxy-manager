import { IconEdit, IconPlus, IconTrash } from "@tabler/icons-react";
import { useState } from "react";
import { Alert } from "react-bootstrap";
import { deleteOidcProvider, testOidcProvider } from "src/api/backend";
import { Button, Loading } from "src/components";
import { useOidcProviders } from "src/hooks";
import { T } from "src/locale";
import { showDeleteConfirmModal, showOidcProviderModal } from "src/modals";
import { showObjectSuccess } from "src/notifications";

export default function OidcProviders() {
	const { data, isLoading, error } = useOidcProviders();
	const [testingId, setTestingId] = useState<number | null>(null);
	const [testResult, setTestResult] = useState<string | null>(null);

	const handleDelete = async (id: number) => {
		await deleteOidcProvider(id);
		showObjectSuccess("oidc-provider", "deleted");
	};

	const handleTest = async (id: number) => {
		setTestingId(id);
		setTestResult(null);
		try {
			const result = await testOidcProvider(id);
			setTestResult(`OK: ${result.issuer}`);
		} catch (err: any) {
			setTestResult(`Failed: ${err.message}`);
		}
		setTestingId(null);
	};

	if (isLoading) {
		return (
			<div className="card-body">
				<div className="mb-3">
					<Loading noLogo />
				</div>
			</div>
		);
	}

	if (error) {
		return (
			<div className="card-body">
				<div className="mb-3">
					<Alert variant="danger" show>
						{error.message}
					</Alert>
				</div>
			</div>
		);
	}

	return (
		<div className="card-body">
			<Alert variant="info" show={!!testResult} onClose={() => setTestResult(null)} dismissible>
				{testResult}
			</Alert>
			<div className="mb-3 text-end">
				<Button actionType="primary" className="bg-teal" onClick={() => showOidcProviderModal("new")}>
					<IconPlus size={16} />
					<T id="object.add" tData={{ object: "oidc-provider" }} />
				</Button>
			</div>
			{!data?.length && (
				<div className="empty">
					<p className="empty-title">
						<T id="object.empty" tData={{ objects: "oidc-providers" }} />
					</p>
				</div>
			)}
			{!!data?.length && (
				<div className="table-responsive">
					<table className="table table-vcenter">
						<thead>
							<tr>
								<th>
									<T id="column.name" />
								</th>
								<th>
									<T id="oidc-provider.discovery-url" />
								</th>
								<th>
									<T id="oidc-provider.client-id" />
								</th>
								<th>
									<T id="oidc-provider.scopes" />
								</th>
								<th className="text-end" />
							</tr>
						</thead>
						<tbody>
							{data.map((provider) => (
								<tr key={provider.id}>
									<td>
										{provider.name}
										{provider.hasSecret && (
											<div className="text-muted">
												<T id="oidc-provider.secret-set" />
											</div>
										)}
									</td>
									<td className="text-muted">{provider.discoveryUrl}</td>
									<td className="text-muted">{provider.clientId}</td>
									<td className="text-muted">{provider.scopes}</td>
									<td className="text-end">
										<button
											type="button"
											className="btn btn-sm"
											onClick={() => provider.id && handleTest(provider.id)}
											disabled={testingId === provider.id}
										>
											<T id="oidc-provider.test" />
										</button>
										<button
											type="button"
											className="btn btn-sm btn-ghost"
											onClick={() => provider.id && showOidcProviderModal(provider.id)}
										>
											<IconEdit size={16} />
										</button>
										<button
											type="button"
											className="btn btn-sm btn-ghost btn-danger"
											onClick={() =>
												provider.id &&
												showDeleteConfirmModal({
													title: <T id="object.delete" tData={{ object: "oidc-provider" }} />,
													onConfirm: () => handleDelete(provider.id as number),
													invalidations: [["oidc-providers"], ["access-lists"]],
													children: (
														<T id="object.delete.content" tData={{ object: "oidc-provider" }} />
													),
												})
											}
										>
											<IconTrash size={16} />
										</button>
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}
		</div>
	);
}
