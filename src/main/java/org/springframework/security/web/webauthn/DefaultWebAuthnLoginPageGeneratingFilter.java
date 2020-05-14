package org.springframework.security.web.webauthn;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.Base64Utils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

/**
 * @author Rob Winch
 */
public class DefaultWebAuthnLoginPageGeneratingFilter extends OncePerRequestFilter {
	private RequestMatcher matches = new AntPathRequestMatcher("/login/webauthn", "GET");

	private Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs = request -> Collections
			.emptyMap();

	private final WebAuthnManager manager;

	private WebAuthnParamsRepository paramsRepository = new WebAuthnParamsRepository();

	public DefaultWebAuthnLoginPageGeneratingFilter(WebAuthnManager manager) {
		this.manager = manager;
	}

	/**
	 * Sets a Function used to resolve a Map of the hidden inputs where the key is the
	 * name of the input and the value is the value of the input. Typically this is used
	 * to resolve the CSRF token.
	 * @param resolveHiddenInputs the function to resolve the inputs
	 */
	public void setResolveHiddenInputs(
			Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs) {
		Assert.notNull(resolveHiddenInputs, "resolveHiddenInputs cannot be null");
		this.resolveHiddenInputs = resolveHiddenInputs;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (this.matches.matches(request)) {
			writeRegistrationPageHtml(request, response);
			return;
		}
		filterChain.doFilter(request, response);
	}

	private void writeRegistrationPageHtml(HttpServletRequest request,
			HttpServletResponse response) throws IOException {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		response.setContentType("text/html;charset=UTF-8");

		WebAuthnLoginParameters params = this.manager.createLoginParametersFor(authentication);
		String challenge = Base64Utils.encodeToUrlSafeString(params.getChallenge());
		this.paramsRepository.saveLoginParams(request, response, params);
		String credentialId = Base64Utils
				.encodeToUrlSafeString(params.getCredentialId());
		response.getWriter().write("<!DOCTYPE html>\n"
				+ "<html xmlns:th=\"https://www.thymeleaf.org\">\n"
				+ "<head>\n"
				+ "    <title>Log In - WebAuthn</title>\n"
				+ "\n"
				+ "    <meta name=\"webAuthnChallenge\" content=\"" + challenge + "\" content=\"\" />\n"
				+ "    <meta name=\"webAuthnCredentialId\" content=\"" + credentialId + "\" content=\"\" />\n"
				+ "    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n"
				+ "    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n"
				+ "</head>\n"
				+ "<body>\n"
				+ "<div class=\"container\">\n"
				+ "<form id=\"login\" class=\"form-signin\" action=\"" + request.getContextPath() + "/login/webauthn\" method=\"post\">\n"
				+ "    <h2 class=\"form-signin-heading\">Log In - WebAuthn</h2>\n"
				+ "    <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Log In</button>\n"
				+ "\n"
				+ "    <input id=\"credentialId\" name=\"credentialId\" type=\"hidden\" />\n"
				+ "    <input id=\"clientDataJSON\" name=\"clientDataJSON\" type=\"hidden\" />\n"
				+ "    <input id=\"authenticatorData\" name=\"authenticatorData\" type=\"hidden\" />\n"
				+ "    <input id=\"signature\" name=\"signature\" type=\"hidden\" />\n"
				+ "    <input id=\"clientExtensions\" name=\"clientExtensions\" type=\"hidden\" />\n"
				+ renderHiddenInputs(request)
				+ "</form>\n"
				+ "</div>\n"
				+ "\n"
				+ "<script\n"
				+ "    src=\"https://code.jquery.com/jquery-3.4.1.js\"\n"
				+ "    integrity=\"sha256-WpOohJOqMqqyKL9FccASB9O0KwACQJpFTUBLTYOVvVU=\"\n"
				+ "    crossorigin=\"anonymous\"></script>\n"
				+ "<script type=\"text/javascript\">\"use strict\";!function(r){for(var e=\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_\",t=new Uint8Array(256),n=0;n<e.length;n++)t[e.charCodeAt(n)]=n;r.decodeBase64url=function(r){for(var e=r.length,n=\"=\"===r.charAt(e-2)?2:\"=\"===r.charAt(e-1)?1:0,a=new ArrayBuffer(3*e/4-n),c=new Uint8Array(a),o=0,s=0;s<e;s+=4){var h=t[r.charCodeAt(s)],u=t[r.charCodeAt(s+1)],i=t[r.charCodeAt(s+2)],A=t[r.charCodeAt(s+3)];c[o++]=h<<2|u>>4,c[o++]=(15&u)<<4|i>>2,c[o++]=(3&i)<<6|63&A}return a},r.encodeBase64url=function(r){for(var t=new Uint8Array(r),n=t.length,a=\"\",c=0;c<n;c+=3)a+=e[t[c]>>2],a+=e[(3&t[c])<<4|t[c+1]>>4],a+=e[(15&t[c+1])<<2|t[c+2]>>6],a+=e[63&t[c+2]];switch(n%3){case 1:a=a.substring(0,a.length-2);break;case 2:a=a.substring(0,a.length-1)}return a}}(\"undefined\"==typeof exports?this.base64url={}:exports);</script>\n"
				+ "<script type=\"text/javascript\">\n"
				+ "if (!window.PublicKeyCredential) { /* Client not capable. Handle error. */ }\n"
				+ "\n"
				+ "function login() {\n"
				+ "    var challenge = $(\"meta[name=webAuthnChallenge]\").attr(\"content\");\n"
				+ "    var credentialIds = $(\"meta[name=webAuthnCredentialId]\").attr(\"content\");\n"
				+ "    const publicKeyCredentialRequestOptions = {\n"
				+ "        challenge: base64url.decodeBase64url(challenge),\n"
				+ "        allowCredentials: [{\n"
				+ "            id: base64url.decodeBase64url(credentialIds),\n"
				+ "            type: 'public-key',\n"
				+ "            transports: ['usb', 'ble', 'nfc'],\n"
				+ "        }],\n"
				+ "        timeout: 60000,\n"
				+ "    };\n"
				+ "\n"
				+ "    return navigator.credentials.get({\n"
				+ "        publicKey: publicKeyCredentialRequestOptions\n"
				+ "    }).then(function (credential) {\n"
				+ "        $(\"#credentialId\").val(credential.id);\n"
				+ "        $(\"#clientDataJSON\").val(base64url.encodeBase64url(credential.response.clientDataJSON));\n"
				+ "        $(\"#authenticatorData\").val(base64url.encodeBase64url(credential.response.authenticatorData));\n"
				+ "        $(\"#signature\").val(base64url.encodeBase64url(credential.response.signature));\n"
				+ "        $(\"#clientExtensions\").val(JSON.stringify(credential.getClientExtensionResults()));\n"
				+ "        $('#login').submit();\n"
				+ "    });\n"
				+ "}\n"
				+ "$(document).ready(function() {\n"
				+ "    $(\"#login\").submit(function(e) {\n"
				+ "        var f = this;\n"
				+ "        login().then(r => f.submit());\n"
				+ "        return false;\n"
				+ "    });\n"
				+ "});\n"
				+ "</script>\n"
				+ "</body>\n"
				+ "</html>");
	}

	private String renderHiddenInputs(HttpServletRequest request) {
		StringBuilder sb = new StringBuilder();
		for (Map.Entry<String, String> input : this.resolveHiddenInputs.apply(request).entrySet()) {
			sb.append("<input name=\"").append(input.getKey()).append("\" type=\"hidden\" value=\"").append(input.getValue()).append("\" />\n");
		}
		return sb.toString();
	}
}
