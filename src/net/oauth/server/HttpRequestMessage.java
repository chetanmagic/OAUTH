/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth.server;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.http.HttpServletRequest;

import net.oauth.OAuth;
import net.oauth.OAuthMessage;

public class HttpRequestMessage extends OAuthMessage {
	private final HttpServletRequest request;

	public HttpRequestMessage(HttpServletRequest request, String URL) {
		super(request.getMethod(), URL, getParameters(request));
		this.request = request;
		copyHeaders(request, getHeaders());
	}

	public InputStream getBodyAsStream() throws IOException {
		return this.request.getInputStream();
	}

	public String getBodyEncoding() {
		return this.request.getCharacterEncoding();
	}

	private static void copyHeaders(HttpServletRequest request, Collection<Map.Entry<String, String>> into) {
		Enumeration names = request.getHeaderNames();
		if (names != null)
			while (names.hasMoreElements()) {
				String name = (String) names.nextElement();
				Enumeration values = request.getHeaders(name);
				if (values != null)
					while (values.hasMoreElements())
						into.add(new OAuth.Parameter(name, (String) values.nextElement()));
			}
	}

	public static List<OAuth.Parameter> getParameters(HttpServletRequest request) {
		List list = new ArrayList();
		for (Enumeration headers = request.getHeaders("Authorization"); (headers != null)
				&& (headers.hasMoreElements());) {
			String header = (String) headers.nextElement();

			Iterator localIterator = OAuthMessage.decodeAuthorization(header).iterator();

			while (localIterator.hasNext()) {
				OAuth.Parameter parameter = (OAuth.Parameter) localIterator.next();
				if (!("realm".equalsIgnoreCase(parameter.getKey()))) {
					list.add(parameter);
				}
			}
		}
		for (Iterator<Entry<String, String[]>> header = request.getParameterMap().entrySet().iterator(); header.hasNext();) {
			Object e = header.next();
			Map.Entry entry = (Map.Entry) e;
			String name = (String) entry.getKey();
			for (String value : (String[]) entry.getValue()) {
				list.add(new OAuth.Parameter(name, value));
			}
		}
		return list;
	}
}