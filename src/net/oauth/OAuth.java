/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class OAuth {
	public static final String VERSION_1_0 = "1.0";
	public static final String ENCODING = "UTF-8";
	public static final String FORM_ENCODED = "application/x-www-form-urlencoded";
	public static final String OAUTH_CONSUMER_KEY = "oauth_consumer_key";
	public static final String OAUTH_TOKEN = "oauth_token";
	public static final String OAUTH_TOKEN_SECRET = "oauth_token_secret";
	public static final String OAUTH_SIGNATURE_METHOD = "oauth_signature_method";
	public static final String OAUTH_SIGNATURE = "oauth_signature";
	public static final String OAUTH_TIMESTAMP = "oauth_timestamp";
	public static final String OAUTH_NONCE = "oauth_nonce";
	public static final String OAUTH_VERSION = "oauth_version";
	public static final String HMAC_SHA1 = "HMAC-SHA1";
	public static final String RSA_SHA1 = "RSA-SHA1";
	public static final String REQUEST_METHOD_POST = "POST";

	public static boolean isFormEncoded(String contentType) {
		if (contentType == null) {
			return false;
		}
		int semi = contentType.indexOf(";");
		if (semi >= 0) {
			contentType = contentType.substring(0, semi);
		}
		return "application/x-www-form-urlencoded".equalsIgnoreCase(contentType.trim());
	}

	public static String formEncode(Iterable<? extends Map.Entry> parameters) throws IOException {
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		formEncode(parameters, b);
		return new String(b.toByteArray());
	}

	public static void formEncode(Iterable<? extends Map.Entry> parameters, OutputStream into) throws IOException {
		if (parameters != null) {
			boolean first = true;
			for (Map.Entry parameter : parameters) {
				if (first)
					first = false;
				else {
					into.write(38);
				}
				into.write(percentEncode(toString(parameter.getKey())).getBytes());
				into.write(61);
				into.write(percentEncode(toString(parameter.getValue())).getBytes());
			}
		}
	}

	public static List<Parameter> decodeForm(String form) {
		List list = new ArrayList();
		if (!(isEmpty(form))) {
			for (String nvp : form.split("\\&")) {
				int equals = nvp.indexOf(61);
				String value;
				String name;
				if (equals < 0) {
					name = decodePercent(nvp);
					value = null;
				} else {
					name = decodePercent(nvp.substring(0, equals));
					value = decodePercent(nvp.substring(equals + 1));
				}
				list.add(new Parameter(name, value));
			}
		}
		return list;
	}

	public static String percentEncode(Iterable values) {
		StringBuilder p = new StringBuilder();
		for (Iterator localIterator = values.iterator(); localIterator.hasNext();) {
			Object v = localIterator.next();
			if (p.length() > 0) {
				p.append("&");
			}
			p.append(percentEncode(toString(v)));
		}
		return p.toString();
	}

	public static String percentEncode(String s) {
		if (s == null)
			return "";
		try {
			return URLEncoder.encode(s, "UTF-8").replace("+", "%20").replace("*", "%2A").replace("%7E", "~");
		} catch (UnsupportedEncodingException wow) {
			throw new RuntimeException(wow.getMessage(), wow);
		}
	}

	public static String decodePercent(String s) {
		try {
			return URLDecoder.decode(s, "UTF-8");
		} catch (UnsupportedEncodingException wow) {
			throw new RuntimeException(wow.getMessage(), wow);
		}
	}

	public static Map<String, String> newMap(Iterable<? extends Map.Entry> from) {
		Map map = new HashMap();
		if (from != null) {
			for (Map.Entry f : from) {
				String key = toString(f.getKey());
				if (!(map.containsKey(key))) {
					map.put(key, toString(f.getValue()));
				}
			}
		}
		return map;
	}

	public static List<Parameter> newList(String[] parameters) {
		List list = new ArrayList(parameters.length / 2);
		for (int p = 0; p + 1 < parameters.length; p += 2) {
			list.add(new Parameter(parameters[p], parameters[(p + 1)]));
		}
		return list;
	}

	private static final String toString(Object from) {
		return ((from == null) ? null : from.toString());
	}

	public static String addParameters(String url, String[] parameters) throws IOException {
		return addParameters(url, newList(parameters));
	}

	public static String addParameters(String url, Iterable<? extends Map.Entry<String, String>> parameters)
			throws IOException {
		String form = formEncode(parameters);
		if ((form == null) || (form.length() <= 0)) {
			return url;
		}
		return url + ((url.indexOf("?") < 0) ? '?' : '&') + form;
	}

	public static boolean isEmpty(String str) {
		return ((str == null) || (str.length() == 0));
	}

	public static class Parameter implements Map.Entry<String, String> {
		private final String key;
		private String value;

		public Parameter(String key, String value) {
			this.key = key;
			this.value = value;
		}

		public String getKey() {
			return this.key;
		}

		public String getValue() {
			return this.value;
		}

		public String setValue(String value) {
			try {
				return this.value;
			} finally {
				this.value = value;
			}
		}

		public String toString() {
			return OAuth.percentEncode(getKey()) + '=' + OAuth.percentEncode(getValue());
		}

		public int hashCode() {
			int prime = 31;
			int result = 1;
			result = prime * result + ((this.key == null) ? 0 : this.key.hashCode());
			result = prime * result + ((this.value == null) ? 0 : this.value.hashCode());
			return result;
		}

		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (super.getClass() != obj.getClass())
				return false;
			Parameter that = (Parameter) obj;

			if (!(this.key.equals(that.key))) {
				return false;
			} else {
				return true;
			}
		}
	}

	public static class Problems {
		public static final String TOKEN_NOT_AUTHORIZED = "token_not_authorized";
		public static final String INVALID_USED_NONCE = "invalid_used_nonce";
		public static final String SIGNATURE_INVALID = "signature_invalid";
		public static final String INVALID_EXPIRED_TOKEN = "invalid_expired_token";
		public static final String INVALID_CONSUMER_KEY = "invalid_consumer_key";
		public static final String CONSUMER_KEY_REFUSED = "consumer_key_refused";
		public static final String TIMESTAMP_REFUSED = "timestamp_refused";
		public static final String PARAMETER_REJECTED = "parameter_rejected";
		public static final String PARAMETER_ABSENT = "parameter_absent";
		public static final String VERSION_REJECTED = "version_rejected";
		public static final String SIGNATURE_METHOD_REJECTED = "signature_method_rejected";
		public static final String OAUTH_PARAMETERS_ABSENT = "oauth_parameters_absent";
		public static final String OAUTH_PARAMETERS_REJECTED = "oauth_parameters_rejected";
		public static final String OAUTH_ACCEPTABLE_TIMESTAMPS = "oauth_acceptable_timestamps";
		public static final String OAUTH_ACCEPTABLE_VERSIONS = "oauth_acceptable_versions";
	}
}