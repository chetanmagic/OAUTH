/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth;

import java.util.HashMap;
import java.util.Map;

public class OAuthProblemException extends OAuthException {
	public static final String OAUTH_PROBLEM = "oauth_problem";

	@Deprecated
	public static final String HTTP_STATUS_CODE = "HTTP status";
	private final Map<String, Object> parameters = new HashMap();
	private static final long serialVersionUID = 1L;

	public OAuthProblemException() {
	}

	public OAuthProblemException(String problem) {
		super(problem);
		if (problem != null)
			this.parameters.put("oauth_problem", problem);
	}

	public String getMessage() {
		String msg = super.getMessage();
		if (msg != null)
			return msg;
		msg = getProblem();
		if (msg != null)
			return msg;
		Object response = getParameters().get("HTTP response");
		if (response != null) {
			msg = response.toString();
			int eol = msg.indexOf("\n");
			if (eol < 0) {
				eol = msg.indexOf("\r");
			}
			if (eol >= 0) {
				msg = msg.substring(0, eol);
			}
			msg = msg.trim();
			if (msg.length() > 0) {
				return msg;
			}
		}
		response = Integer.valueOf(getHttpStatusCode());
		if (response != null) {
			return "HTTP status " + response;
		}
		return null;
	}

	public void setParameter(String name, Object value) {
		getParameters().put(name, value);
	}

	public Map<String, Object> getParameters() {
		return this.parameters;
	}

	public String getProblem() {
		return ((String) getParameters().get("oauth_problem"));
	}

	public int getHttpStatusCode() {
		Object code = getParameters().get("HTTP status");
		if (code == null)
			return 200;
		if (code instanceof Number) {
			return ((Number) code).intValue();
		}
		return Integer.parseInt(code.toString());
	}
}