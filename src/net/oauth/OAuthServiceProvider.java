/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth;

import java.io.Serializable;

public class OAuthServiceProvider implements Serializable {
	private static final long serialVersionUID = 3306534392621038574L;
	public final String requestTokenURL;
	public final String userAuthorizationURL;
	public final String accessTokenURL;

	public OAuthServiceProvider(String requestTokenURL, String userAuthorizationURL, String accessTokenURL) {
		this.requestTokenURL = requestTokenURL;
		this.userAuthorizationURL = userAuthorizationURL;
		this.accessTokenURL = accessTokenURL;
	}
}