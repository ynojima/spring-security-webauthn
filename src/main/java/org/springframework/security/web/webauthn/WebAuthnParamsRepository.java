package org.springframework.security.web.webauthn;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Rob Winch
 */
public class WebAuthnParamsRepository {

	private String registrationParamsAttrName = "registrationParamsAttr";

	private String loginParamsAttrName = "loginParamsAttr";

	public void saveRegistrationParams(HttpServletRequest request, HttpServletResponse response, WebAuthnRegistrationParameters params) {
		request.getSession().setAttribute(this.registrationParamsAttrName, params);
	}

	public WebAuthnRegistrationParameters loadRegistrationParams(HttpServletRequest request) {
		return (WebAuthnRegistrationParameters) request.getSession().getAttribute(this.registrationParamsAttrName);
	}

	public void saveLoginParams(HttpServletRequest request, HttpServletResponse response, WebAuthnLoginParameters params) {
		request.getSession().setAttribute(this.loginParamsAttrName, params);
	}

	public WebAuthnLoginParameters loadLoginParams(HttpServletRequest request) {
		return (WebAuthnLoginParameters) request.getSession().getAttribute(this.loginParamsAttrName);
	}
}
