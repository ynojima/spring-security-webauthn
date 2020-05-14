package org.springframework.security.web.webauthn;

import java.net.URL;

/**
 * @author Rob Winch
 */
public class WebAuthnRegistrationRequest {

	private AuthenticatorAttestationResponse response;

	private WebAuthnRegistrationParameters parameters;

	private URL origin;

	public URL getOrigin() {
		return this.origin;
	}

	public void setOrigin(URL origin) {
		this.origin = origin;
	}

	public WebAuthnRegistrationParameters getParameters() {
		return this.parameters;
	}

	public void setParameters(WebAuthnRegistrationParameters parameters) {
		this.parameters = parameters;
	}

	public AuthenticatorAttestationResponse getResponse() {
		return this.response;
	}

	public void setResponse(AuthenticatorAttestationResponse response) {
		this.response = response;
	}
}
