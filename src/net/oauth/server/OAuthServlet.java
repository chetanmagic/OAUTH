/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth.server;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.oauth.OAuth;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;

public class OAuthServlet {
	private static final Integer SC_FORBIDDEN = new Integer(403);

	private static final Map<String, Integer> PROBLEM_TO_HTTP_CODE = new HashMap();

	static {
		Integer SC_BAD_REQUEST = new Integer(400);
		Integer SC_SERVICE_UNAVAILABLE = new Integer(503);
		Integer SC_UNAUTHORIZED = new Integer(401);
		PROBLEM_TO_HTTP_CODE.put("version_rejected", SC_BAD_REQUEST);
		PROBLEM_TO_HTTP_CODE.put("parameter_absent", SC_BAD_REQUEST);
		PROBLEM_TO_HTTP_CODE.put("parameter_rejected", SC_BAD_REQUEST);
		PROBLEM_TO_HTTP_CODE.put("timestamp_refused", SC_BAD_REQUEST);
		PROBLEM_TO_HTTP_CODE.put("signature_method_rejected", SC_BAD_REQUEST);
		PROBLEM_TO_HTTP_CODE.put("consumer_key_refused", SC_SERVICE_UNAVAILABLE);

		PROBLEM_TO_HTTP_CODE.put("invalid_consumer_key", SC_UNAUTHORIZED);
		PROBLEM_TO_HTTP_CODE.put("invalid_expired_token", SC_UNAUTHORIZED);
		PROBLEM_TO_HTTP_CODE.put("signature_invalid", SC_UNAUTHORIZED);
		PROBLEM_TO_HTTP_CODE.put("invalid_used_nonce", SC_UNAUTHORIZED);
		PROBLEM_TO_HTTP_CODE.put("token_not_authorized", SC_UNAUTHORIZED);
	}

	public static OAuthMessage getMessage(HttpServletRequest request, String URL) {
		if (URL == null) {
			URL = request.getRequestURL().toString();
		}
		int q = URL.indexOf(63);
		if (q >= 0) {
			URL = URL.substring(0, q);
		}

		return new HttpRequestMessage(request, URL);
	}

	public static String getRequestURL(HttpServletRequest request) {
		StringBuffer url = request.getRequestURL();
		String queryString = request.getQueryString();
		if (queryString != null) {
			url.append("?").append(queryString);
		}
		return url.toString();
	}

	public static void handleException(HttpServletResponse response, Exception e, String realm)
			throws IOException, ServletException {
		handleException(response, e, realm, true);
	}

	public static void handleException(HttpServletResponse response, Exception e, String realm, boolean sendBody)
			throws IOException, ServletException {
		if (e instanceof OAuthProblemException) {
			OAuthProblemException problem = (OAuthProblemException) e;
			Object httpCode = problem.getParameters().get("HTTP status");
			if (httpCode == null) {
				httpCode = PROBLEM_TO_HTTP_CODE.get(problem.getProblem());
			}
			if (httpCode == null) {
				httpCode = SC_FORBIDDEN;
			}
			response.reset();
			response.setStatus(Integer.parseInt(httpCode.toString()));
			OAuthMessage message = new OAuthMessage(null, null, problem.getParameters().entrySet());
			response.addHeader("WWW-Authenticate", message.getAuthorizationHeader(realm));
			if (sendBody)
				sendForm(response, message.getParameters());
		} else {
			if (e instanceof IOException)
				throw ((IOException) e);
			if (e instanceof ServletException)
				throw ((ServletException) e);
			if (e instanceof RuntimeException) {
				throw ((RuntimeException) e);
			}
			throw new ServletException(e);
		}
	}

	public static void sendForm(HttpServletResponse response, Iterable<? extends Map.Entry> parameters)
			throws IOException {
		response.resetBuffer();
		response.setContentType("application/x-www-form-urlencoded;charset=UTF-8");

		OAuth.formEncode(parameters, response.getOutputStream());
	}

	public static String htmlEncode(String s) {
		if (s == null) {
			return null;
		}
		StringBuilder html = new StringBuilder(s.length());
		for (char c : s.toCharArray()) {
			switch (c) {
				case '<' :
					html.append("&lt;");
					break;
				case '>' :
					html.append("&gt;");
					break;
				case '&' :
					html.append("&amp;");

					break;
				case '"' :
					html.append("&quot;");
					break;
				default :
					html.append(c);
			}
		}

		return html.toString();
	}
}