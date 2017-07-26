/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth;

public class OAuthException extends Exception {
	private static final long serialVersionUID = 1L;

	protected OAuthException() {
	}

	public OAuthException(String message) {
		super(message);
	}

	public OAuthException(Throwable cause) {
		super(cause);
	}

	public OAuthException(String message, Throwable cause) {
		super(message, cause);
	}
}