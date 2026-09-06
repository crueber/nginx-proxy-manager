import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { Field, Form, Formik } from "formik";
import { type ReactNode, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import { type OidcProvider, testOidcProvider } from "src/api/backend";
import { Button, Loading } from "src/components";
import { useOidcProvider, useSetOidcProvider } from "src/hooks";
import { intl, T } from "src/locale";
import { OIDC_DEFAULT_SCOPES, OIDC_DEFAULT_USERNAME_CLAIM, validateOidcProvider } from "src/modules/Oidc";
import { validateString } from "src/modules/Validations";
import { showObjectSuccess } from "src/notifications";

const showOidcProviderModal = (id: number | "new") => {
	EasyModal.show(OidcProviderModal, { id });
};

interface Props extends InnerModalProps {
	id: number | "new";
}

const OidcProviderModal = EasyModal.create(({ id, visible, remove }: Props) => {
	const { data, isLoading, error } = useOidcProvider(id);
	const { mutate: setOidcProvider } = useSetOidcProvider();
	const [errorMsg, setErrorMsg] = useState<ReactNode | null>(null);
	const [testMsg, setTestMsg] = useState<ReactNode | null>(null);
	const [isTesting, setIsTesting] = useState(false);
	const [isSubmitting, setIsSubmitting] = useState(false);

	const onTest = async () => {
		if (id === "new" || isTesting) return;
		setIsTesting(true);
		setTestMsg(null);
		try {
			const result = await testOidcProvider(id);
			setTestMsg(intl.formatMessage({ id: "oidc-provider.test-ok" }, { issuer: result.issuer }));
		} catch (err: any) {
			setTestMsg(`${intl.formatMessage({ id: "oidc-provider.test-failed" })}: ${err.message}`);
		}
		setIsTesting(false);
	};

	const onSubmit = async (values: any, { setSubmitting }: any) => {
		if (isSubmitting) return;

		const vErr = validateOidcProvider(values);
		if (vErr) {
			setErrorMsg(vErr);
			return;
		}

		setIsSubmitting(true);
		setErrorMsg(null);

		// Never send an empty secret: blank means "keep the stored secret".
		const payload: OidcProvider = {
			id: id === "new" ? undefined : (id as number),
			name: values.name?.trim(),
			discoveryUrl: values.discoveryUrl?.trim(),
			clientId: values.clientId?.trim(),
			scopes: values.scopes?.trim() || OIDC_DEFAULT_SCOPES,
			usernameClaim: values.usernameClaim?.trim() || OIDC_DEFAULT_USERNAME_CLAIM,
			groupsClaim: values.groupsClaim?.trim() || null,
		};
		if (values.clientSecret) {
			payload.clientSecret = values.clientSecret;
		}

		setOidcProvider(payload, {
			onError: (err: any) => setErrorMsg(<T id={err.message} />),
			onSuccess: () => {
				showObjectSuccess("oidc-provider", "saved");
				remove();
			},
			onSettled: () => {
				setIsSubmitting(false);
				setSubmitting(false);
			},
		});
	};

	const textField = (name: string, labelId: string, opts: { required?: boolean; placeholder?: string; type?: string } = {}) => (
		<Field name={name} validate={opts.required ? validateString(1, 255) : undefined}>
			{({ field, form }: any) => (
				<div className="mb-3">
					<label className="form-label" htmlFor={`oidc-${name}`}>
						<T id={labelId} />
					</label>
					<input
						id={`oidc-${name}`}
						type={opts.type || "text"}
						autoComplete="off"
						required={opts.required}
						placeholder={opts.placeholder}
						className="form-control"
						{...field}
					/>
					{form.errors[name] && form.touched[name] ? (
						<div className="invalid-feedback">{form.errors[name]}</div>
					) : null}
				</div>
			)}
		</Field>
	);

	return (
		<Modal show={visible} onHide={remove}>
			{!isLoading && error && (
				<Alert variant="danger" className="m-3">
					{error?.message || "Unknown error"}
				</Alert>
			)}
			{isLoading && <Loading noLogo />}
			{!isLoading && data && (
				<Formik
					initialValues={
						{
							name: data?.name || "",
							discoveryUrl: data?.discoveryUrl || "",
							clientId: data?.clientId || "",
							clientSecret: "",
							scopes: data?.scopes || OIDC_DEFAULT_SCOPES,
							usernameClaim: data?.usernameClaim || OIDC_DEFAULT_USERNAME_CLAIM,
							groupsClaim: data?.groupsClaim || "",
						} as any
					}
					onSubmit={onSubmit}
				>
					<Form>
						<Modal.Header closeButton>
							<Modal.Title>
								<T id={data?.id ? "object.edit" : "object.add"} tData={{ object: "oidc-provider" }} />
							</Modal.Title>
						</Modal.Header>
						<Modal.Body>
							<Alert variant="danger" show={!!errorMsg} onClose={() => setErrorMsg(null)} dismissible>
								{errorMsg}
							</Alert>
							<Alert variant="info" show={!!testMsg} onClose={() => setTestMsg(null)} dismissible>
								{testMsg}
							</Alert>
							{textField("name", "column.name", { required: true })}
							{textField("discoveryUrl", "oidc-provider.discovery-url", {
								required: true,
								placeholder: "https://auth.example.com/realms/npm",
							})}
							{textField("clientId", "oidc-provider.client-id", { required: true })}
							{textField("clientSecret", "oidc-provider.client-secret", {
								type: "password",
								placeholder:
									id === "new"
										? undefined
										: intl.formatMessage({ id: "oidc-provider.client-secret.placeholder" }),
							})}
							{textField("scopes", "oidc-provider.scopes")}
							{textField("usernameClaim", "oidc-provider.username-claim")}
							{textField("groupsClaim", "oidc-provider.groups-claim")}
						</Modal.Body>
						<Modal.Footer>
							{id !== "new" && (
								<Button onClick={onTest} disabled={isTesting || isSubmitting}>
									<T id="oidc-provider.test" />
								</Button>
							)}
							<Button data-bs-dismiss="modal" onClick={remove} disabled={isSubmitting}>
								<T id="cancel" />
							</Button>
							<Button
								type="submit"
								actionType="primary"
								className="ms-auto bg-cyan"
								data-bs-dismiss="modal"
								isLoading={isSubmitting}
								disabled={isSubmitting}
							>
								<T id="save" />
							</Button>
						</Modal.Footer>
					</Form>
				</Formik>
			)}
		</Modal>
	);
});

export { showOidcProviderModal };
