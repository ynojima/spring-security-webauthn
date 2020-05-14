package org.springframework.security.web.webauthn;

/**
 * @author Rob Winch
 */
public class WebAuthnRegistrationParameters {
	private byte[] challenge;

	private byte[] userId;

	private boolean userVerificationRequired;

	public byte[] getChallenge() {
		return this.challenge;
	}

	public void setChallenge(byte[] challenge) {
		this.challenge = challenge;
	}

	public byte[] getUserId() {
		return this.userId;
	}

	public void setUserId(byte[] userId) {
		this.userId = userId;
	}

	public boolean isUserVerificationRequired() {
		return this.userVerificationRequired;
	}

	public void setUserVerificationRequired(boolean userVerificationRequired) {
		this.userVerificationRequired = userVerificationRequired;
	}
}
