package example.webauthn;

import example.webauthn.security.MultiFactorAuthentication;
import example.webauthn.security.MultiFactorAuthenticationRequiredException;
import example.webauthn.security.MultiFactorRegistrationRequiredException;
import example.webauthn.security.WebAuthnAuthenticatorRepository;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.webauthn.AuthenticatorAttestationResponse;
import org.springframework.stereotype.Component;

/**
 * @author Rob Winch
 */
@Component
public class Mfa {
	private final WebAuthnAuthenticatorRepository authenticators;

	public Mfa(WebAuthnAuthenticatorRepository authenticators) {
		this.authenticators = authenticators;
	}

	public boolean require(Authentication authentication) {
		if (authentication instanceof AnonymousAuthenticationToken) {
			return false;
		}
		if (authentication instanceof MultiFactorAuthentication) {
			return true;
		}
		AuthenticatorAttestationResponse response = this.authenticators.load(authentication);
		if (response == null) {
			throw new MultiFactorRegistrationRequiredException();
		}
		throw new MultiFactorAuthenticationRequiredException();
	}
}
