/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth.signature;

import net.oauth.OAuth;
import net.oauth.OAuthException;

class PLAINTEXT extends OAuthSignatureMethod {
	private String signature = null;

	public String getSignature(String baseString) {
		return getSignature();
	}

	protected boolean isValid(String signature, String baseString) throws OAuthException {
		return signature.equals(getSignature());
	}

	private synchronized String getSignature() {
		if (this.signature == null) {
			this.signature = OAuth.percentEncode(getConsumerSecret()) + '&' + OAuth.percentEncode(getTokenSecret());
		}
		return this.signature;
	}

	public void setConsumerSecret(String consumerSecret) {
		synchronized (this) {
			this.signature = null;
		}
		super.setConsumerSecret(consumerSecret);
	}

	public void setTokenSecret(String tokenSecret) {
		synchronized (this) {
			this.signature = null;
		}
		super.setTokenSecret(tokenSecret);
	}
}