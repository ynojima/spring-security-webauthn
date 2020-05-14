package org.springframework.security.web.webauthn;

import org.springframework.security.core.Authentication;

import java.net.URL;

/**
 * @author Rob Winch
 */
public class WebAuthnLoginRequest {
	private byte[] credentialId;
	private byte[] clientDataJSON;
	private byte[] authenticatorData;
	private byte[] signature;
	private WebAuthnLoginParameters loginParameters;
	private URL origin;
	private Authentication authentication;

	public byte[] getCredentialId() {
		return this.credentialId;
	}

	public void setCredentialId(byte[] credentialId) {
		this.credentialId = credentialId;
	}

	public byte[] getClientDataJSON() {
		return this.clientDataJSON;
	}

	public void setClientDataJSON(byte[] clientDataJSON) {
		this.clientDataJSON = clientDataJSON;
	}

	public byte[] getAuthenticatorData() {
		return this.authenticatorData;
	}

	public void setAuthenticatorData(byte[] authenticatorData) {
		this.authenticatorData = authenticatorData;
	}

	public byte[] getSignature() {
		return this.signature;
	}

	public void setSignature(byte[] signature) {
		this.signature = signature;
	}

	public WebAuthnLoginParameters getLoginParameters() {
		return this.loginParameters;
	}

	public void setLoginParameters(WebAuthnLoginParameters loginParameters) {
		this.loginParameters = loginParameters;
	}

	public URL getOrigin() {
		return this.origin;
	}

	public void setOrigin(URL origin) {
		this.origin = origin;
	}

	public Authentication getAuthentication() {
		return this.authentication;
	}

	public void setAuthentication(Authentication authentication) {
		this.authentication = authentication;
	}
}
