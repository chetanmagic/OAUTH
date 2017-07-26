/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth.signature;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.oauth.OAuth;
import net.oauth.OAuthException;

class HMAC_SHA1 extends OAuthSignatureMethod {
	private static final String ENCODING = "UTF-8";
	private static final String MAC_NAME = "HmacSHA1";
	private SecretKey key = null;

	protected String getSignature(String baseString) throws OAuthException {
		try {
			String signature = base64Encode(computeSignature(baseString));
			return signature;
		} catch (GeneralSecurityException e) {
			throw new OAuthException(e);
		} catch (UnsupportedEncodingException e) {
			throw new OAuthException(e);
		}
	}

	protected boolean isValid(String signature, String baseString) throws OAuthException {
		try {
			byte[] expected = computeSignature(baseString);
			byte[] actual = decodeBase64(signature);
			return Arrays.equals(expected, actual);
		} catch (GeneralSecurityException e) {
			throw new OAuthException(e);
		} catch (UnsupportedEncodingException e) {
			throw new OAuthException(e);
		}
	}

	private byte[] computeSignature(String baseString) throws GeneralSecurityException, UnsupportedEncodingException {
		SecretKey key = null;
		synchronized (this) {
			if (this.key == null) {
				String keyString = OAuth.percentEncode(getConsumerSecret()) + '&'
						+ OAuth.percentEncode(getTokenSecret());
				byte[] keyBytes = keyString.getBytes("UTF-8");
				this.key = new SecretKeySpec(keyBytes, "HmacSHA1");
			}
			key = this.key;
		}
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(key);
		byte[] text = baseString.getBytes("UTF-8");
		return mac.doFinal(text);
	}

	public void setConsumerSecret(String consumerSecret) {
		synchronized (this) {
			this.key = null;
		}
		super.setConsumerSecret(consumerSecret);
	}

	public void setTokenSecret(String tokenSecret) {
		synchronized (this) {
			this.key = null;
		}
		super.setTokenSecret(tokenSecret);
	}
}