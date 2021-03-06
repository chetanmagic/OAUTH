/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth.http;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.oauth.client.ExcerptInputStream;

public class HttpMessage {
	public String method;
	public URL url;
	public final List<Map.Entry<String, String>> headers;
	protected InputStream body;
	public static final String REQUEST = "HTTP request";
	public static final String RESPONSE = "HTTP response";
	public static final String ACCEPT_ENCODING = "Accept-Encoding";
	public static final String CONTENT_ENCODING = "Content-Encoding";
	public static final String CONTENT_LENGTH = "Content-Length";
	public static final String CONTENT_TYPE = "Content-Type";
	public static final String DEFAULT_CHARSET = "ISO-8859-1";
	private static final Pattern CHARSET = Pattern.compile("; *charset *= *([^;\"]*|\"([^\"]|\\\\\")*\")(;|$)");

	public HttpMessage() {
		this(null, null);
	}

	public HttpMessage(String method, URL url) {
		this(method, url, null);
	}

	public HttpMessage(String method, URL url, InputStream body) {
		this.headers = new ArrayList();
		this.body = null;

		this.method = method;
		this.url = url;
		this.body = body;
	}

	public final String getHeader(String name) {
		String value = null;
		for (Map.Entry header : this.headers) {
			if (equalsIgnoreCase(name, (String) header.getKey())) {
				value = (String) header.getValue();
			}
		}
		return value;
	}

	public String removeHeaders(String name) {
		String value = null;
		for (Iterator i = this.headers.iterator(); i.hasNext();) {
			Map.Entry header = (Map.Entry) i.next();
			if (equalsIgnoreCase(name, (String) header.getKey())) {
				value = (String) header.getValue();
				i.remove();
			}
		}
		return value;
	}

	public final String getContentCharset() {
		return getCharset(getHeader("Content-Type"));
	}

	public final InputStream getBody() throws IOException {
		if (this.body == null) {
			InputStream raw = openBody();
			if (raw != null) {
				this.body = new ExcerptInputStream(raw);
			}
		}
		return this.body;
	}

	protected InputStream openBody() throws IOException {
		return null;
	}

	public void dump(Map<String, Object> into) throws IOException {
	}

	private static boolean equalsIgnoreCase(String x, String y) {
		if (x == null) {
			return (y == null);
		}
		return x.equalsIgnoreCase(y);
	}

	private static final String getCharset(String mimeType) {
		if (mimeType != null) {
			Matcher m = CHARSET.matcher(mimeType);
			if (m.find()) {
				String charset = m.group(1);
				if ((charset.length() >= 2) && (charset.charAt(0) == '"')
						&& (charset.charAt(charset.length() - 1) == '"')) {
					charset = charset.substring(1, charset.length() - 1);
					charset = charset.replace("\\\"", "\"");
				}
				return charset;
			}
		}
		return "ISO-8859-1";
	}
}