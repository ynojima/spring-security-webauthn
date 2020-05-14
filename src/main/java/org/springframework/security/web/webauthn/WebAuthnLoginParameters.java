package org.springframework.security.web.webauthn;

import java.io.Serializable;

/**
 * @author Rob Winch
 */
public class WebAuthnLoginParameters implements Serializable {

	private byte[] challenge;

	private byte[] credentialId;

	private boolean userVerificationRequired;

	public byte[] getChallenge() {
		return this.challenge;
	}

	public void setChallenge(byte[] challenge) {
		this.challenge = challenge;
	}

	public byte[] getCredentialId() {
		return this.credentialId;
	}

	public void setCredentialId(byte[] credentialId) {
		this.credentialId = credentialId;
	}

	public boolean isUserVerificationRequired() {
		return this.userVerificationRequired;
	}

	public void setUserVerificationRequired(boolean userVerificationRequired) {
		this.userVerificationRequired = userVerificationRequired;
	}
}
