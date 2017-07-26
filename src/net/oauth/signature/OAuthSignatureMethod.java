/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth.signature;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.codec.binary.Base64;

import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;

public abstract class OAuthSignatureMethod {
	public static final String _ACCESSOR = "-Accessor";
	private String consumerSecret;
	private String tokenSecret;
	private static final Base64 BASE64 = new Base64();

	private static final Map<String, Class> NAME_TO_CLASS = new ConcurrentHashMap();

	static {
		registerMethodClass("HMAC-SHA1", HMAC_SHA1.class);
		registerMethodClass("PLAINTEXT", PLAINTEXT.class);
		registerMethodClass("RSA-SHA1", RSA_SHA1.class);
		registerMethodClass("HMAC-SHA1-Accessor", HMAC_SHA1.class);
		registerMethodClass("PLAINTEXT-Accessor", PLAINTEXT.class);
	}

	public void sign(OAuthMessage message) throws OAuthException, IOException, URISyntaxException {
		message.addParameter(new OAuth.Parameter("oauth_signature", getSignature(message)));
	}

	public void validate(OAuthMessage message) throws IOException, OAuthException, URISyntaxException {
		message.requireParameters(new String[]{"oauth_signature"});
		String signature = message.getSignature();
		String baseString = getBaseString(message);
		if (!(isValid(signature, baseString))) {
			OAuthProblemException problem = new OAuthProblemException("signature_invalid");
			problem.setParameter("oauth_signature", signature);
			problem.setParameter("oauth_signature_base_string", baseString);
			problem.setParameter("oauth_signature_method", message.getSignatureMethod());
			throw problem;
		}
	}

	protected String getSignature(OAuthMessage message) throws OAuthException, IOException, URISyntaxException {
		String baseString = getBaseString(message);
		String signature = getSignature(baseString);

		return signature;
	}

	protected void initialize(String name, OAuthAccessor accessor) throws OAuthException {
		String secret = accessor.consumer.consumerSecret;
		if (name.endsWith("-Accessor")) {
			String key = "oauth_accessor_secret";
			Object accessorSecret = accessor.getProperty("oauth_accessor_secret");
			if (accessorSecret == null) {
				accessorSecret = accessor.consumer.getProperty("oauth_accessor_secret");
			}
			if (accessorSecret != null) {
				secret = accessorSecret.toString();
			}
		}
		if (secret == null) {
			secret = "";
		}
		setConsumerSecret(secret);
	}

	protected abstract String getSignature(String paramString) throws OAuthException;

	protected abstract boolean isValid(String paramString1, String paramString2) throws OAuthException;

	protected String getConsumerSecret() {
		return this.consumerSecret;
	}

	protected void setConsumerSecret(String consumerSecret) {
		this.consumerSecret = consumerSecret;
	}

	public String getTokenSecret() {
		return this.tokenSecret;
	}

	public void setTokenSecret(String tokenSecret) {
		this.tokenSecret = tokenSecret;
	}

	public static String getBaseString(OAuthMessage message) throws IOException, URISyntaxException {
		String url = message.URL;
		int q = url.indexOf(63);
		List parameters;
		if (q < 0) {
			parameters = message.getParameters();
		} else {
			parameters = new ArrayList();
			parameters.addAll(OAuth.decodeForm(message.URL.substring(q + 1)));
			parameters.addAll(message.getParameters());
			url = url.substring(0, q);
		}
		return OAuth.percentEncode(message.method.toUpperCase()) + '&' + OAuth.percentEncode(normalizeUrl(url)) + '&'
				+ OAuth.percentEncode(normalizeParameters(parameters));
	}

	protected static String normalizeUrl(String url) throws URISyntaxException {
		URI uri = new URI(url);
		String scheme = uri.getScheme().toLowerCase();
		String authority = uri.getAuthority().toLowerCase();
		boolean dropPort = ((scheme.equals("http")) && (uri.getPort() == 80))
				|| ((scheme.equals("https")) && (uri.getPort() == 443));
		if (dropPort) {
			int index = authority.lastIndexOf(":");
			if (index >= 0) {
				authority = authority.substring(0, index);
			}
		}
		String path = uri.getRawPath();
		if ((path == null) || (path.length() <= 0)) {
			path = "/";
		}

		return scheme + "://" + authority + path;
	}

	protected static String normalizeParameters(Collection<? extends Map.Entry> parameters) throws IOException {
		if (parameters == null) {
			return "";
		}
		List p = new ArrayList(parameters.size());
		for (Map.Entry parameter : parameters) {
			if (!("oauth_signature".equals(parameter.getKey()))) {
				p.add(new ComparableParameter(parameter));
			}
		}
		Collections.sort(p);
		return OAuth.formEncode(getParameters(p));
	}

	public static byte[] decodeBase64(String s) {
		return BASE64.decode(s.getBytes());
	}

	public static String base64Encode(byte[] b) {
		return new String(BASE64.encode(b));
	}

	public static OAuthSignatureMethod newSigner(OAuthMessage message, OAuthAccessor accessor)
			throws IOException, OAuthException {
		message.requireParameters(new String[]{"oauth_signature_method"});
		OAuthSignatureMethod signer = newMethod(message.getSignatureMethod(), accessor);
		signer.setTokenSecret(accessor.tokenSecret);
		return signer;
	}

	public static OAuthSignatureMethod newMethod(String name, OAuthAccessor accessor) throws OAuthException {
		try {
			Class methodClass = (Class) NAME_TO_CLASS.get(name);
			if (methodClass != null) {
				OAuthSignatureMethod method = (OAuthSignatureMethod) methodClass.newInstance();
				method.initialize(name, accessor);
				return method;
			}
			OAuthProblemException problem = new OAuthProblemException("signature_method_rejected");
			String acceptable = OAuth.percentEncode(NAME_TO_CLASS.keySet());
			if (acceptable.length() > 0) {
				problem.setParameter("oauth_acceptable_signature_methods", acceptable.toString());
			}
			throw problem;
		} catch (InstantiationException e) {
			throw new OAuthException(e);
		} catch (IllegalAccessException e) {
			throw new OAuthException(e);
		}
	}

	public static void registerMethodClass(String name, Class clazz) {
		NAME_TO_CLASS.put(name, clazz);
	}

	private static List<Map.Entry> getParameters(Collection<ComparableParameter> parameters) {
		if (parameters == null) {
			return null;
		}
		List list = new ArrayList(parameters.size());
		for (ComparableParameter parameter : parameters) {
			list.add(parameter.value);
		}
		return list;
	}

	private static class ComparableParameter implements Comparable<ComparableParameter> {
		final Map.Entry value;
		private final String key;

		ComparableParameter(Map.Entry value) {
			this.value = value;
			String n = toString(value.getKey());
			String v = toString(value.getValue());
			this.key = OAuth.percentEncode(n) + ' ' + OAuth.percentEncode(v);
		}

		private static String toString(Object from) {
			return ((from == null) ? null : from.toString());
		}

		public int compareTo(ComparableParameter that) {
			return this.key.compareTo(that.key);
		}

		public String toString() {
			return this.key;
		}
	}
}