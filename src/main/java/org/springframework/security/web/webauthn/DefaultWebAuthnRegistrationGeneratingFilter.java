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
public class DefaultWebAuthnRegistrationGeneratingFilter extends OncePerRequestFilter {
	private RequestMatcher matches = new AntPathRequestMatcher("/webauthn/register", "GET");

	private WebAuthnParamsRepository webAuthnRequests = new WebAuthnParamsRepository();

	private final WebAuthnManager manager;

	private Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs = request -> Collections
			.emptyMap();

	public DefaultWebAuthnRegistrationGeneratingFilter(WebAuthnManager manager) {
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
		WebAuthnRegistrationParameters params = this.manager
				.createRegistrationParametersFor(authentication);
		this.webAuthnRequests.saveRegistrationParams(request, response, params);
		response.getWriter().write("<!DOCTYPE html>\n"
				+ "<html lang=\"en\" xmlns:th=\"https://www.thymeleaf.org\">\n"
				+ "<head>\n"
				+ "    <meta charset=\"utf-8\">\n"
				+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
				+ "    <meta name=\"description\" content=\"\">\n"
				+ "    <meta name=\"author\" content=\"\">\n"
				+ "    <title>WebAuthn - Registration</title>\n"
				+ "    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n"
				+ "    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n"
				+ "    <meta name=\"webAuthnChallenge\" content=\"" + Base64Utils.encodeToUrlSafeString(params.getChallenge()) + "\" />\n"
				+ "    <meta name=\"userId\" content=\"" + Base64Utils.encodeToUrlSafeString(params.getUserId()) + "\" />\n"
				+ "</head>\n"
				+ "<body>\n"
				+ "<div class=\"container\">\n"
				+ "    <form id=\"register\" class=\"form-signin\" method=\"post\" action=\"" + request.getContextPath() + "/webauthn/register\">\n"
				+ "        <h2 class=\"form-signin-heading\">WebAuthn - Registration</h2>\n"
				+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Register</button>\n"
				+ "        <input type=\"hidden\" id=\"clientDataJSON\" name=\"clientDataJSON\">\n"
				+ "        <input type=\"hidden\" id=\"attestationObject\" name=\"attestationObject\">\n"
				+ "        <input type=\"hidden\" id=\"clientExtensions\" name=\"clientExtensions\">\n"
				+ renderHiddenInputs(request)
				+ "    </form>\n"
				+ "</div>\n"
				+ "    <script\n"
				+ "            src=\"https://code.jquery.com/jquery-3.4.1.js\"\n"
				+ "            integrity=\"sha256-WpOohJOqMqqyKL9FccASB9O0KwACQJpFTUBLTYOVvVU=\"\n"
				+ "            crossorigin=\"anonymous\"></script>\n"
				+ "    <script type=\"text/javascript\">\"use strict\";!function(r){for(var e=\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_\",t=new Uint8Array(256),n=0;n<e.length;n++)t[e.charCodeAt(n)]=n;r.decodeBase64url=function(r){for(var e=r.length,n=\"=\"===r.charAt(e-2)?2:\"=\"===r.charAt(e-1)?1:0,a=new ArrayBuffer(3*e/4-n),c=new Uint8Array(a),o=0,s=0;s<e;s+=4){var h=t[r.charCodeAt(s)],u=t[r.charCodeAt(s+1)],i=t[r.charCodeAt(s+2)],A=t[r.charCodeAt(s+3)];c[o++]=h<<2|u>>4,c[o++]=(15&u)<<4|i>>2,c[o++]=(3&i)<<6|63&A}return a},r.encodeBase64url=function(r){for(var t=new Uint8Array(r),n=t.length,a=\"\",c=0;c<n;c+=3)a+=e[t[c]>>2],a+=e[(3&t[c])<<4|t[c+1]>>4],a+=e[(15&t[c+1])<<2|t[c+2]>>6],a+=e[63&t[c+2]];switch(n%3){case 1:a=a.substring(0,a.length-2);break;case 2:a=a.substring(0,a.length-1)}return a}}(\"undefined\"==typeof exports?this.base64url={}:exports);</script>\n"
				+ "    <script type=\"text/javascript\">\n"
				+ "        if (!window.PublicKeyCredential) { /* Client not capable. Handle error. */ }\n"
				+ "\n"
				+ "        function register() {\n"
				+ "            var challenge = $(\"meta[name=webAuthnChallenge]\").attr(\"content\");\n"
				+ "            var userId = $(\"meta[name=userId]\").attr(\"content\");\n"
				+ "            var publicKey = {\n"
				+ "                // The challenge is produced by the server; see the Security Considerations\n"
				+ "                challenge: base64url.decodeBase64url(challenge),\n"
				+ "\n"
				+ "                // Relying Party:\n"
				+ "                rp: {\n"
				+ "                    name: \"Web Application\"\n"
				+ "                },\n"
				+ "\n" + "                // User:\n"
				+ "                user: {\n"
				+ "                    id: base64url.decodeBase64url(userId),\n"
				+ "                    name: \"alex.p.mueller@example.com\",\n"
				+ "                    displayName: \"Alex P. Müller\",\n"
				+ "                },\n"
				+ "\n"
				+ "                // This Relying Party will accept either an ES256 or RS256 credential, but\n"
				+ "                // prefers an ES256 credential.\n"
				+ "                pubKeyCredParams: [\n"
				+ "                    {\n"
				+ "                        type: \"public-key\",\n"
				+ "                        alg: -7 // \"ES256\" as registered in the IANA COSE Algorithms registry\n"
				+ "                    },\n"
				+ "                    {\n"
				+ "                        type: \"public-key\",\n"
				+ "                        alg: -257 // Value registered by this specification for \"RS256\"\n"
				+ "                    }\n"
				+ "                ],\n"
				+ "\n"
				+ "                authenticatorSelection: {\n"
				+ "                    // Try to use UV if possible. This is also the default.\n"
				+ "                    userVerification: \"preferred\"\n"
				+ "                },\n"
				+ "\n"
				+ "                timeout: 360000,  // 6 minutes\n"
				+ "                excludeCredentials: [], // No exclude list of PKCredDescriptors\n"
				+ "                extensions: {\"loc\": true}  // Include location information\n"
				+ "                // in attestation\n"
				+ "            };\n"
				+ "\n"
				+ "            // Note: The following call will cause the authenticator to display UI.\n"
				+ "            return navigator.credentials.create({publicKey})\n"
				+ "                .then(function (credential) {\n"
				+ "                    console.log('Created credentials');\n"
				+ "                    $('#clientDataJSON').val(base64url.encodeBase64url(credential.response.clientDataJSON));\n"
				+ "                    $('#attestationObject').val(base64url.encodeBase64url(credential.response.attestationObject));\n"
				+ "                    $('#clientExtensions').val(JSON.stringify(credential.getClientExtensionResults()));\n"
				+ "                    console.log(\"Updated the hidden inputs\");\n"
				+ "                }).catch(function (e) {\n"
				+ "                    console.error(\"Error:%s, Message:%s\", e.name, e.message);\n"
				+ "                });\n"
				+ "        }\n"
				+ "        $(document).ready(function() {\n"
				+ "            $(\"#register\").submit(function(e) {\n"
				+ "                var f = this;\n"
				+ "                register().then(r => f.submit());\n"
				+ "                return false;\n"
				+ "            });\n"
				+ "        });\n"
				+ "    </script>\n"
				+ "</body></html>");
	}

	private String renderHiddenInputs(HttpServletRequest request) {
		StringBuilder sb = new StringBuilder();
		for (Map.Entry<String, String> input : this.resolveHiddenInputs.apply(request).entrySet()) {
			sb.append("<input name=\"").append(input.getKey()).append("\" type=\"hidden\" value=\"").append(input.getValue()).append("\" />\n");
		}
		return sb.toString();
	}
}
