/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class OAuthConsumer implements Serializable {
	private static final long serialVersionUID = -2258581186977818580L;
	public final String callbackURL;
	public final String consumerKey;
	public final String consumerSecret;
	public final OAuthServiceProvider serviceProvider;
	private final Map<String, Object> properties = new HashMap();
	public static final String ACCESSOR_SECRET = "oauth_accessor_secret";

	public OAuthConsumer(String callbackURL, String consumerKey, String consumerSecret,
			OAuthServiceProvider serviceProvider) {
		this.callbackURL = callbackURL;
		this.consumerKey = consumerKey;
		this.consumerSecret = consumerSecret;
		this.serviceProvider = serviceProvider;
	}

	public Object getProperty(String name) {
		return this.properties.get(name);
	}

	public void setProperty(String name, Object value) {
		this.properties.put(name, value);
	}
}