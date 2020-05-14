package org.springframework.security.web.webauthn;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.server.ServerProperty;
import example.webauthn.security.WebAuthnAuthenticatorRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 *
 *
 * @author Rob Winch
 */
public class WebAuthnManager {
	private SecureRandom random = new SecureRandom();

	private ObjectConverter objectConverter = new ObjectConverter();
	// com.webauthn4j.WebAuthnManager.createNonStrictWebAuthnManager() returns a com.webauthn4j.WebAuthnManager instance
	// which doesn't validate an attestation statement. It is recommended configuration for most web application.
	// If you are building enterprise web application and need to validate the attestation statement, use the constructor of
	// WebAuthnRegistrationContextValidator and provide validators you like
	private com.webauthn4j.WebAuthnManager webAuthnManager = com.webauthn4j.WebAuthnManager.createNonStrictWebAuthnManager(this.objectConverter);

	private Map<String, byte[]> usernameToUserId = new ConcurrentHashMap<>();

	private final WebAuthnAuthenticatorRepository authenticators;

	public WebAuthnManager(WebAuthnAuthenticatorRepository authenticators) {
		this.authenticators = authenticators;
	}

	public WebAuthnRegistrationParameters createRegistrationParametersFor(Authentication authentication) {
		WebAuthnRegistrationParameters result = new WebAuthnRegistrationParameters();
		result.setChallenge(randomBytes());
		result.setUserId(userId(authentication));
		return result;
	}

	// FIXME: This should return a registration (should not do any saving in the manager)
	public void register(WebAuthnRegistrationRequest request) {
		WebAuthnRegistrationParameters webAuthnRegistrationParameters = request.getParameters();
		byte[] attestationObject = request.getResponse().getAttestationObject();
		byte[] clientDataJSON = request.getResponse().getClientDataJSON();

		// Server properties
		Origin origin = new Origin(request.getOrigin().toExternalForm()); /* set origin */;
		String rpId = origin.getHost();
		byte[] base64Challenge = webAuthnRegistrationParameters.getChallenge();
		Challenge challenge = new DefaultChallenge(base64Challenge);
		// FIXME: should populate this
		byte[] tokenBindingId = null /* set tokenBindingId */;
		ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);
		boolean userVerificationRequired = webAuthnRegistrationParameters.isUserVerificationRequired();

		RegistrationRequest registrationRequest = new RegistrationRequest(attestationObject, clientDataJSON);
		RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty, userVerificationRequired);

		this.webAuthnManager.validate(registrationRequest, registrationParameters);

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		// FIXME: should save something w/ a counter on it
		this.authenticators.save(authentication, request.getResponse());
	}

	public WebAuthnLoginParameters createLoginParametersFor(Authentication authentication) {
		Authenticator authenticator = load(authentication);
		WebAuthnLoginParameters result = new WebAuthnLoginParameters();
		result.setChallenge(randomBytes());
		result.setCredentialId(authenticator.getAttestedCredentialData().getCredentialId());
		return result;
	}

	// FIXME: login

	public void login(WebAuthnLoginRequest request) {
		Authenticator authenticator = load(request.getAuthentication());
		if (authenticator == null) {
			throw new IllegalStateException("No authenticator found");
		}

		// Client properties

		// Server properties
		Origin origin = new Origin(request.getOrigin().toExternalForm()); /* set origin */;
		String rpId = origin.getHost();
		Challenge challenge = new DefaultChallenge(request.getLoginParameters().getChallenge());
		// FIXME: should populate this
		byte[] tokenBindingId = null /* set tokenBindingId */;
		ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);
		boolean userVerificationRequired = false;

		AuthenticationRequest authenticationRequest = new AuthenticationRequest(
				request.getCredentialId(),
				request.getAuthenticatorData(),
				request.getClientDataJSON(),
				request.getSignature()
		);
		AuthenticationParameters authenticationParameters = new AuthenticationParameters(serverProperty, authenticator, userVerificationRequired);

		AuthenticationData authenticationData = this.webAuthnManager.validate(authenticationRequest, authenticationParameters);

		authenticator.setCounter(authenticationData.getAuthenticatorData().getSignCount());
	}

	private Authenticator load(Authentication authentication) {
		AuthenticatorAttestationResponse response = this.authenticators.load(authentication);
		if (response == null) {
			return null;
		}
		CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter(this.objectConverter);
		AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(this.objectConverter);

		CollectedClientData collectedClientData = collectedClientDataConverter.convert(response.getClientDataJSON());
		AttestationObject attestationObject = attestationObjectConverter.convert(response.getAttestationObject());

		AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = attestationObject.getAuthenticatorData();
		return new AuthenticatorImpl(
				authenticatorData.getAttestedCredentialData(),
				attestationObject.getAttestationStatement(),
				authenticatorData.getSignCount()
		);
	}

	private byte[] userId(Authentication authentication) {
		if (authentication == null) {
			return randomBytes();
		}
		String username = authentication.getName();
		return this.usernameToUserId.computeIfAbsent(username, u -> randomBytes());
	}

	private byte[] randomBytes() {
		byte[] result = new byte[64];
		this.random.nextBytes(result);
		return result;
	}
}
