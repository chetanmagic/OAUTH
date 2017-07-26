/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.oauth.signature.OAuthSignatureMethod;

public class OAuthMessage {
	public String method;
	public String URL;
	private final List<Map.Entry<String, String>> parameters;
	private Map<String, String> parameterMap;
	private boolean parametersAreComplete = false;
	private final List<Map.Entry<String, String>> headers = new ArrayList();

	@Deprecated
	public static final String HTTP_REQUEST = "HTTP request";

	@Deprecated
	public static final String HTTP_RESPONSE = "HTTP response";
	public static final String AUTH_SCHEME = "OAuth";

	@Deprecated
	public static final String CONTENT_TYPE = "Content-Type";
	public static final String GET = "GET";
	public static final String POST = "POST";
	public static final String PUT = "PUT";
	public static final String DELETE = "DELETE";
	private static final Pattern AUTHORIZATION = Pattern.compile("\\s*(\\w*)\\s+(.*)");
	private static final Pattern NVP = Pattern.compile("(\\S*)\\s*\\=\\s*\"([^\"]*)\"");

	public OAuthMessage(String method, String URL, Collection<? extends Map.Entry> parameters) {
		this.method = method;
		this.URL = URL;
		if (parameters == null) {
			this.parameters = new ArrayList();
		} else {
			this.parameters = new ArrayList(parameters.size());
			for (Map.Entry p : parameters){
				OAuth.Parameter newparam=new OAuth.Parameter(toString(p.getKey()), toString(p.getValue()));
				if(!this.parameters.contains(newparam)){
					this.parameters.add(newparam);
				}
			}
		}
	}

	public String toString() {
		return "OAuthMessage(" + this.method + ", " + this.URL + ", " + this.parameters + ")";
	}

	private void beforeGetParameter() throws IOException {
		if (!(this.parametersAreComplete)) {
			completeParameters();
			this.parametersAreComplete = true;
		}
	}

	protected void completeParameters() throws IOException {
	}

	public List<Map.Entry<String, String>> getParameters() throws IOException {
		beforeGetParameter();
		return Collections.unmodifiableList(this.parameters);
	}

	public void addParameter(String key, String value) {
		addParameter(new OAuth.Parameter(key, value));
	}

	public void addParameter(Map.Entry<String, String> parameter) {
		this.parameters.add(parameter);
		this.parameterMap = null;
	}

	public void addParameters(Collection<? extends Map.Entry<String, String>> parameters) {
		this.parameters.addAll(parameters);
		this.parameterMap = null;
	}

	public String getParameter(String name) throws IOException {
		return ((String) getParameterMap().get(name));
	}

	public String getConsumerKey() throws IOException {
		return getParameter("oauth_consumer_key");
	}

	public String getToken() throws IOException {
		return getParameter("oauth_token");
	}

	public String getSignatureMethod() throws IOException {
		return getParameter("oauth_signature_method");
	}

	public String getSignature() throws IOException {
		return getParameter("oauth_signature");
	}

	protected Map<String, String> getParameterMap() throws IOException {
		beforeGetParameter();
		if (this.parameterMap == null) {
			this.parameterMap = OAuth.newMap(this.parameters);
		}
		return this.parameterMap;
	}

	public String getBodyType() {
		return getHeader("Content-Type");
	}

	public String getBodyEncoding() {
		return "ISO-8859-1";
	}

	public final String getHeader(String name) {
		String value = null;
		for (Map.Entry header : getHeaders()) {
			if (name.equalsIgnoreCase((String) header.getKey())) {
				value = (String) header.getValue();
			}
		}
		return value;
	}

	public final List<Map.Entry<String, String>> getHeaders() {
		return this.headers;
	}

	public final String readBodyAsString() throws IOException {
		InputStream body = getBodyAsStream();
		return readAll(body, getBodyEncoding());
	}

	public InputStream getBodyAsStream() throws IOException {
		return null;
	}

	public Map<String, Object> getDump() throws IOException {
		Map into = new HashMap();
		dump(into);
		return into;
	}

	protected void dump(Map<String, Object> into) throws IOException {
		into.put("URL", this.URL);
		if (!(this.parametersAreComplete))
			return;
		try {
			into.putAll(getParameterMap());
		} catch (Exception localException) {
		}
	}

	public void requireParameters(String[] names) throws OAuthProblemException, IOException {
		Set present = getParameterMap().keySet();
		List absent = new ArrayList();
		for (String required : names) {
			if (!(present.contains(required))) {
				absent.add(required);
			}
		}
		if (!(absent.isEmpty())) {
			OAuthProblemException problem = new OAuthProblemException("parameter_absent");
			problem.setParameter("oauth_parameters_absent", OAuth.percentEncode(absent));
			throw problem;
		}
	}

	public void addRequiredParameters(OAuthAccessor accessor) throws OAuthException, IOException, URISyntaxException {
		Map pMap = OAuth.newMap(this.parameters);
		if ((pMap.get("oauth_token") == null) && (accessor.accessToken != null)) {
			addParameter("oauth_token", accessor.accessToken);
		}
		OAuthConsumer consumer = accessor.consumer;
		if (pMap.get("oauth_consumer_key") == null) {
			addParameter("oauth_consumer_key", consumer.consumerKey);
		}
		String signatureMethod = (String) pMap.get("oauth_signature_method");
		if (signatureMethod == null) {
			signatureMethod = (String) consumer.getProperty("oauth_signature_method");
			if (signatureMethod == null) {
				signatureMethod = "HMAC-SHA1";
			}
			addParameter("oauth_signature_method", signatureMethod);
		}
		if (pMap.get("oauth_timestamp") == null) {
			addParameter("oauth_timestamp", Long.toString(System.currentTimeMillis() / 1000L));
		}
		if (pMap.get("oauth_nonce") == null) {
			addParameter("oauth_nonce", Long.toString(System.nanoTime()));
		}
		if (pMap.get("oauth_version") == null) {
			addParameter("oauth_version", "1.0");
		}
		sign(accessor);
	}

	public void sign(OAuthAccessor accessor) throws IOException, OAuthException, URISyntaxException {
		OAuthSignatureMethod.newSigner(this, accessor).sign(this);
	}

	public void validateMessage(OAuthAccessor accessor, OAuthValidator validator)
			throws OAuthException, IOException, URISyntaxException {
		validator.validateMessage(this, accessor);
	}

	@Deprecated
	public void validateSignature(OAuthAccessor accessor) throws OAuthException, IOException, URISyntaxException {
		OAuthSignatureMethod.newSigner(this, accessor).validate(this);
	}

	public String getAuthorizationHeader(String realm) throws IOException {
		StringBuilder into = new StringBuilder();
		if (realm != null) {
			into.append(" realm=\"").append(OAuth.percentEncode(realm)).append('"');
		}
		beforeGetParameter();
		if (this.parameters != null) {
			for (Map.Entry parameter : this.parameters) {
				String name = toString(parameter.getKey());
				if (name.startsWith("oauth_")) {
					if (into.length() > 0)
						into.append(",");
					into.append(" ");
					into.append(OAuth.percentEncode(name)).append("=\"");
					into.append(OAuth.percentEncode(toString(parameter.getValue()))).append('"');
				}
			}
		}
		return "OAuth" + into.toString();
	}

	public static String readAll(InputStream from, String encoding) throws IOException {
		if (from == null)
			return null;
		try {
			StringBuilder into = new StringBuilder();
			Reader r = new InputStreamReader(from, encoding);
			char[] s = new char[512];
			int n;
			while ((n = r.read(s)) > 0) {
				into.append(s, 0, n);
			}
			return into.toString();
		} finally {
			from.close();
		}
	}

	public static List<OAuth.Parameter> decodeAuthorization(String authorization) {
		List into = new ArrayList();
		if (authorization != null) {
			Matcher m = AUTHORIZATION.matcher(authorization);
			if ((m.matches()) && ("OAuth".equalsIgnoreCase(m.group(1)))) {
				for (String nvp : m.group(2).split("\\s*,\\s*")) {
					m = NVP.matcher(nvp);
					if (m.matches()) {
						String name = OAuth.decodePercent(m.group(1));
						String value = OAuth.decodePercent(m.group(2));
						into.add(new OAuth.Parameter(name, value));
					}
				}
			}
		}

		return into;
	}

	private static final String toString(Object from) {
		return ((from == null) ? null : from.toString());
	}
}