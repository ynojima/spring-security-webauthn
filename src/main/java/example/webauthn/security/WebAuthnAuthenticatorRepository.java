package example.webauthn.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.webauthn.AuthenticatorAttestationResponse;

/**
 * FIXME: This should be saved per Authentication
 *
 * @author Rob Winch
 */
public class WebAuthnAuthenticatorRepository {
	private AuthenticatorAttestationResponse response;

	public void save(Authentication authentication, AuthenticatorAttestationResponse response) {
		this.response = response;
	}

	public AuthenticatorAttestationResponse load(Authentication authentication) {
		return this.response;
	}
}
