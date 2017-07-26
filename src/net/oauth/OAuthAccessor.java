/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth;

import java.io.IOException;
import java.io.Serializable;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class OAuthAccessor implements Serializable {
	private static final long serialVersionUID = 5590788443138352999L;
	public final OAuthConsumer consumer;
	public String requestToken;
	public String accessToken;
	public String tokenSecret;
	private final Map<String, Object> properties = new HashMap();

	public OAuthAccessor(OAuthConsumer consumer) {
		this.consumer = consumer;
		this.requestToken = null;
		this.accessToken = null;
		this.tokenSecret = null;
	}

	public Object getProperty(String name) {
		return this.properties.get(name);
	}

	public void setProperty(String name, Object value) {
		this.properties.put(name, value);
	}

	public OAuthMessage newRequestMessage(String method, String url, Collection<? extends Map.Entry> parameters)
			throws OAuthException, IOException, URISyntaxException {
		if (method == null) {
			method = (String) getProperty("httpMethod");
			if (method == null) {
				method = (String) this.consumer.getProperty("httpMethod");
				if (method == null) {
					method = "GET";
				}
			}
		}
		OAuthMessage message = new OAuthMessage(method, url, parameters);
		message.addRequiredParameters(this);
		return message;
	}
}