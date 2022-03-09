package com.scsi.pemtojks;

import java.io.BufferedInputStream;
import java.io.InputStream;
import java.io.IOException;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.security.auth.x500.X500Principal;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.converters.PathConverter;


public class App {
	private static final Pattern CN_PAT_RFC1779 = Pattern.compile("CN\\s*=\\s*([A-Za-z0-9._-]+)(,)*");
	private static final String DEFAULT_PASSWORD = "changeit";
	private static final String DEFAULT_KEYSTORE_NAME = "keystore.jks";

	@Parameter(names = "-key", converter = PathConverter.class, required = true)
	private Path keyFile;

	@Parameter(names = "-keypass")
	private String keyPass;

	@Parameter(names = "-cert", converter = PathConverter.class)
	private Path certFile;

	@Parameter(names = "-chain", converter = PathConverter.class, required = true)
	private Path chainFile; // Assume the cert is the first one if no cert file

	@Parameter(names = "-out", converter = PathConverter.class)
	private Path keystoreFile = Path.of(DEFAULT_KEYSTORE_NAME); // Make sure this ends with ".jks"

	@Parameter(names = "-keystorepass")
	private String keystorePass = DEFAULT_PASSWORD;

	@Parameter(names = "-alias")
	private String alias; // Will use the CN from the cert if none specified


	
    public static void main( String[] args ) {
		App app = new App();

		JCommander.newBuilder()
				.addObject(app)
				.build()
				.parse(args);
    }

	public String getCertCN(X509Certificate cert) {
		X500Principal principal = cert.getSubjectX500Principal();
		String canonicalDN = principal.getName(X500Principal.RFC1779);
		Matcher m = CN_PAT_RFC1779.matcher(canonicalDN);
		
		return m.find() ? m.group(1) : "";
	}


	KeyStore newSingleEntryKeystore(RSAPrivateKey key, List<X509Certificate> chain) 
			throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException {
		return newSingleEntryKeystore(key, chain, DEFAULT_PASSWORD);
	}


	KeyStore newSingleEntryKeystore(RSAPrivateKey key, List<X509Certificate> chain, String passwd) 
			throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException {
		// This method assumes that the first cert in the chain is "our" cert. Is that safe???
		KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
		store.load(null, DEFAULT_PASSWORD.toCharArray());

		if (chain != null && !chain.isEmpty()) {
			String alias = getCertCN(chain.get(0));
			if (!"".equals(alias)) {
				store.setKeyEntry(alias, key, passwd.toCharArray(), chain.toArray(new Certificate[chain.size()]));
			}
		}

		return store;
	}

	RSAPrivateKey getPrivateKey(InputStream keyIn) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory kf = KeyFactory.getInstance("RSA"); // This is *probably* a safe assumption

		try {
			String keyData = new String(keyIn.readAllBytes())
					.replace("-----BEGIN PRIVATE KEY-----", "")
					.replaceAll(System.lineSeparator(), "")
					.replace("-----END PRIVATE KEY-----", "");
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(keyData));
			return (RSAPrivateKey) kf.generatePrivate(keySpec);
		} catch (IOException e) {
			System.err.println("Could not read private key: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
	}
		

	List<X509Certificate> getCertChain(InputStream certIn) throws CertificateException {
		List<X509Certificate> certs = new ArrayList<>();
		Certificate nextCert;
		CertificateFactory cf = CertificateFactory.getInstance("X.509");

		try (BufferedInputStream bis = new BufferedInputStream(certIn);) {
			while (bis.available() > 0) {
				nextCert = cf.generateCertificate(bis);
				if (nextCert instanceof X509Certificate) {
					certs.add((X509Certificate) nextCert);
				} else {
					System.err.println("Found a cert of an unexpected type: " + nextCert.getType());
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		return certs;
	}
}
