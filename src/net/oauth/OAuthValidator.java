/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth;

import java.io.IOException;
import java.net.URISyntaxException;

public abstract interface OAuthValidator {
	public abstract void validateMessage(OAuthMessage paramOAuthMessage, OAuthAccessor paramOAuthAccessor)
			throws OAuthException, IOException, URISyntaxException;
}