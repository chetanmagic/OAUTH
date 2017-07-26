/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth;

import java.io.IOException;
import java.net.URISyntaxException;

import net.oauth.signature.OAuthSignatureMethod;

public class SimpleOAuthValidator implements OAuthValidator {
	public static final long DEFAULT_TIMESTAMP_WINDOW = 600000L;
	protected double minVersion = 1.0D;
	protected final double maxVersion;
	protected final long timestampWindow;

	public SimpleOAuthValidator() {
		this(600000L, Double.parseDouble("1.0"));
	}

	public SimpleOAuthValidator(long timestampWindowMsec, double maxVersion) {
		this.minVersion = 1.0D;

		this.timestampWindow = timestampWindowMsec;
		this.maxVersion = maxVersion;
	}

	public void validateMessage(OAuthMessage message, OAuthAccessor accessor)
			throws OAuthException, IOException, URISyntaxException {
		validateVersion(message);
		validateTimestampAndNonce(message);
		validateSignature(message, accessor);
	}

	protected void validateVersion(OAuthMessage message) throws OAuthException, IOException {
		String versionString = message.getParameter("oauth_version");
		if (versionString != null) {
			double version = Double.parseDouble(versionString);
			if ((version < 1.0D) || (this.maxVersion < version)) {
				OAuthProblemException problem = new OAuthProblemException("version_rejected");
				problem.setParameter("oauth_acceptable_versions", "1.0-" + this.maxVersion);
				throw problem;
			}
		}
	}

	protected void validateTimestampAndNonce(OAuthMessage message) throws IOException, OAuthProblemException {
		message.requireParameters(new String[]{"oauth_timestamp", "oauth_nonce"});
		long timestamp = Long.parseLong(message.getParameter("oauth_timestamp")) * 1000L;
		long now = currentTimeMsec();
		long min = now - this.timestampWindow;
		long max = now + this.timestampWindow;
		if ((timestamp < min) || (max < timestamp)) {
			OAuthProblemException problem = new OAuthProblemException("timestamp_refused");
			problem.setParameter("oauth_acceptable_timestamps", min + "-" + max);
			throw problem;
		}
	}

	protected void validateSignature(OAuthMessage message, OAuthAccessor accessor)
			throws OAuthException, IOException, URISyntaxException {
		message.requireParameters(new String[]{"oauth_consumer_key", "oauth_signature_method", "oauth_signature"});
		OAuthSignatureMethod.newSigner(message, accessor).validate(message);
	}

	protected long currentTimeMsec() {
		return System.currentTimeMillis();
	}
}