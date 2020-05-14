package org.springframework.security.web.webauthn;

import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Base64Utils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;

/**
 * @author Rob Winch
 */
public class WebAuthnRegistrationFilter extends OncePerRequestFilter {
	private RequestMatcher matcher = new AntPathRequestMatcher("/webauthn/register",
			"POST");

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private final WebAuthnParamsRepository webAuthnRequests;

	private final WebAuthnManager manager;

	public WebAuthnRegistrationFilter(WebAuthnParamsRepository webAuthnRequests,
			WebAuthnManager manager) {
		this.webAuthnRequests = webAuthnRequests;
		this.manager = manager;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (this.matcher.matches(request)) {
			register(request);
			this.redirectStrategy.sendRedirect(request, response, "/login/webauthn");
			return;
		}
		filterChain.doFilter(request, response);
	}

	private void register(HttpServletRequest request) throws IOException{

		String clientDataJSON = request.getParameter("clientDataJSON");
		String attestationObject = request.getParameter("attestationObject");

		// Client properties
		byte[] clientDataJSONBytes = Base64Utils.decodeFromUrlSafeString(clientDataJSON);
		byte[] attestationObjectBytes = Base64Utils.decodeFromUrlSafeString(attestationObject);

		WebAuthnRegistrationParameters parameters = this.webAuthnRequests.loadRegistrationParams(request);
		AuthenticatorAttestationResponse authenticatorResponse = new AuthenticatorAttestationResponse();
		authenticatorResponse.setAttestationObject(attestationObjectBytes);
		authenticatorResponse.setClientDataJSON(clientDataJSONBytes);
		WebAuthnRegistrationRequest registration = new WebAuthnRegistrationRequest();
		registration.setResponse(authenticatorResponse);
		registration.setParameters(parameters);
		registration.setOrigin(new URL(request.getRequestURL().toString()));

		this.manager.register(registration);
	}
}
