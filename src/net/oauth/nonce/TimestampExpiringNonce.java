/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth.nonce;

public class TimestampExpiringNonce {
	private long validityWindowSeconds = 600L;

	public boolean validateNonce(String consumerKey, long timestamp, String nonce) {
		long nowSeconds = System.currentTimeMillis() / 1000L;

		return (nowSeconds - timestamp <= getValidityWindowSeconds());
	}

	public long getValidityWindowSeconds() {
		return this.validityWindowSeconds;
	}

	public void setValidityWindowSeconds(long validityWindowSeconds) {
		this.validityWindowSeconds = validityWindowSeconds;
	}
}