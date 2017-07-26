/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth.signature;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import net.oauth.OAuthAccessor;
import net.oauth.OAuthException;

public class RSA_SHA1 extends OAuthSignatureMethod {
	public static final String PRIVATE_KEY = "RSA-SHA1.PrivateKey";
	public static final String PUBLIC_KEY = "RSA-SHA1.PublicKey";
	public static final String X509_CERTIFICATE = "RSA-SHA1.X509Certificate";
	private PrivateKey privateKey = null;
	private PublicKey publicKey = null;

	protected void initialize(String name, OAuthAccessor accessor) throws OAuthException {
		super.initialize(name, accessor);

		Object privateKeyObject = accessor.consumer.getProperty("RSA-SHA1.PrivateKey");
		try {
			if (privateKeyObject != null) {
				if (privateKeyObject instanceof PrivateKey)
					this.privateKey = ((PrivateKey) privateKeyObject);
				else if (privateKeyObject instanceof String)
					this.privateKey = getPrivateKeyFromPem((String) privateKeyObject);
				else if (privateKeyObject instanceof byte[])
					this.privateKey = getPrivateKeyFromDer((byte[]) privateKeyObject);
				else {
					throw new IllegalArgumentException(
							"Private key set through RSA_SHA1.PRIVATE_KEY must be of type PrivateKey, String, or byte[], and not "
									+ privateKeyObject.getClass().getName());
				}
			}

			Object publicKeyObject = accessor.consumer.getProperty("RSA-SHA1.PublicKey");
			if (publicKeyObject != null) {
				if (publicKeyObject instanceof PublicKey) {
					this.publicKey = ((PublicKey) publicKeyObject);
					return;
				}
				if (publicKeyObject instanceof String) {
					this.publicKey = getPublicKeyFromPem((String) publicKeyObject);
					return;
				}
				if (publicKeyObject instanceof byte[]) {
					this.publicKey = getPublicKeyFromDer((byte[]) publicKeyObject);
					return;
				}
				throw new IllegalArgumentException(
						"Public key set through RSA_SHA1.PRIVATE_KEY must be of type PublicKey, String, or byte[], and not "
								+ publicKeyObject.getClass().getName());
			}

			Object certObject = accessor.consumer.getProperty("RSA-SHA1.X509Certificate");
			if (certObject != null) {
				if (certObject instanceof X509Certificate)
					this.publicKey = ((X509Certificate) certObject).getPublicKey();
				else if (certObject instanceof String)
					this.publicKey = getPublicKeyFromPemCert((String) certObject);
				else if (certObject instanceof byte[])
					this.publicKey = getPublicKeyFromDerCert((byte[]) certObject);
				else
					throw new IllegalArgumentException(
							"X509Certificate set through RSA_SHA1.X509_CERTIFICATE must be of type X509Certificate, String, or byte[], and not "
									+ certObject.getClass().getName());
			}
		} catch (GeneralSecurityException e) {
			throw new OAuthException(e);
		}
	}

	private PublicKey getPublicKeyFromPemCert(String certObject) throws GeneralSecurityException {
		CertificateFactory fac = CertificateFactory.getInstance("X509");
		ByteArrayInputStream in = new ByteArrayInputStream(certObject.getBytes());
		X509Certificate cert = (X509Certificate) fac.generateCertificate(in);
		return cert.getPublicKey();
	}

	private PublicKey getPublicKeyFromDerCert(byte[] certObject) throws GeneralSecurityException {
		CertificateFactory fac = CertificateFactory.getInstance("X509");
		ByteArrayInputStream in = new ByteArrayInputStream(certObject);
		X509Certificate cert = (X509Certificate) fac.generateCertificate(in);
		return cert.getPublicKey();
	}

	private PublicKey getPublicKeyFromDer(byte[] publicKeyObject) throws GeneralSecurityException {
		KeyFactory fac = KeyFactory.getInstance("RSA");
		EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyObject);
		return fac.generatePublic(pubKeySpec);
	}

	private PublicKey getPublicKeyFromPem(String publicKeyObject) throws GeneralSecurityException {
		return getPublicKeyFromDer(decodeBase64(publicKeyObject));
	}

	private PrivateKey getPrivateKeyFromDer(byte[] privateKeyObject) throws GeneralSecurityException {
		KeyFactory fac = KeyFactory.getInstance("RSA");
		EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privateKeyObject);
		return fac.generatePrivate(privKeySpec);
	}

	private PrivateKey getPrivateKeyFromPem(String privateKeyObject) throws GeneralSecurityException {
		return getPrivateKeyFromDer(decodeBase64(privateKeyObject));
	}

	protected String getSignature(String baseString) throws OAuthException {
		try {
			byte[] signature = sign(baseString.getBytes("UTF-8"));
			return base64Encode(signature);
		} catch (UnsupportedEncodingException e) {
			throw new OAuthException(e);
		} catch (GeneralSecurityException e) {
			throw new OAuthException(e);
		}
	}

	protected boolean isValid(String signature, String baseString) throws OAuthException {
		try {
			return verify(decodeBase64(signature), baseString.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			throw new OAuthException(e);
		} catch (GeneralSecurityException e) {
			throw new OAuthException(e);
		}
	}

	private byte[] sign(byte[] message) throws GeneralSecurityException {
		if (this.privateKey == null) {
			throw new IllegalStateException(
					"need to set private key with OAuthConsumer.setProperty when generating RSA-SHA1 signatures.");
		}

		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initSign(this.privateKey);
		signer.update(message);
		return signer.sign();
	}

	private boolean verify(byte[] signature, byte[] message) throws GeneralSecurityException {
		if (this.publicKey == null) {
			throw new IllegalStateException(
					"need to set public key with  OAuthConsumer.setProperty when verifying RSA-SHA1 signatures.");
		}

		Signature verifier = Signature.getInstance("SHA1withRSA");
		verifier.initVerify(this.publicKey);
		verifier.update(message);
		return verifier.verify(signature);
	}
}