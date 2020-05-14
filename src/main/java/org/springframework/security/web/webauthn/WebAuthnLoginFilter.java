package org.springframework.security.web.webauthn;

import example.webauthn.security.MultiFactorAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Base64Utils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;

/**
 * @author Rob Winch
 */
public class WebAuthnLoginFilter extends AbstractAuthenticationProcessingFilter {
	private final WebAuthnParamsRepository requests;

	private final WebAuthnManager manager;

	public WebAuthnLoginFilter(WebAuthnParamsRepository requests, WebAuthnManager manager) {
		super(new AntPathRequestMatcher("/login/webauthn", "POST"));
		this.requests = requests;
		this.manager = manager;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException, IOException {
		Authentication authentication = SecurityContextHolder.getContext()
				.getAuthentication();

		// Client properties
		byte[] credentialIdBytes = bytes(request, "credentialId");
		byte[] clientDataJSONBytes = bytes(request, "clientDataJSON");
		byte[] authenticatorDataBytes = bytes(request, "authenticatorData");
		byte[] signatureBytes = bytes(request, "signature");

		WebAuthnLoginParameters loginParams = this.requests
				.loadLoginParams(request);

		WebAuthnLoginRequest loginRequest = new WebAuthnLoginRequest();
		loginRequest.setAuthentication(authentication);
		loginRequest.setAuthenticatorData(authenticatorDataBytes);
		loginRequest.setClientDataJSON(clientDataJSONBytes);
		loginRequest.setCredentialId(credentialIdBytes);
		loginRequest.setAuthenticatorData(authenticatorDataBytes);
		loginRequest.setSignature(signatureBytes);
		loginRequest.setOrigin(new URL(request.getRequestURL().toString()));
		loginRequest.setLoginParameters(loginParams);

		this.manager.login(loginRequest);

		return new MultiFactorAuthentication(authentication);
	}

	private byte[] bytes(HttpServletRequest request, String paramName) {
		String value = request.getParameter(paramName);
		if (value == null) {
			return null;
		}
		return Base64Utils.decodeFromUrlSafeString(value);
	}
}
