package com.scsi.pemtojks;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.IOException;
import java.util.Enumeration;
import java.util.List;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import org.junit.jupiter.api.Test;

public class AppTest {
	private final URL selfSignedCertUrl = this.getClass().getResource("self_signed_site_cert.pem");
	private final URL selfSignedKeyUrl = this.getClass().getResource("self_signed_site_priv.pem");
	private final URL caSignedCertUrl = this.getClass().getResource("ca_signed_site_cert.pem");
	private final URL caCertUrl = this.getClass().getResource("ca/dummy_root_ca_cert.pem");
	private final URL caSignedKeyUrl = this.getClass().getResource("ca_signed_site_priv.pem");
	private final String selfSignedCertCN = "PemToJksTesting";
	private final String caSignedCertCN = "PemToJks CA-Signed Cert";
	
	@Test
	void testMain() throws Exception {
		String certFile;
		Certificate keystoreCert;
		Certificate[] keystoreChain;
		PublicKey keystorePubKey;
		KeyStore ks;
		String privKeyFile = Path.of(selfSignedKeyUrl.toURI()).toAbsolutePath().toString();
		String chainFile = Path.of(selfSignedCertUrl.toURI()).toAbsolutePath().toString();
		String keystoreFile = Files.createTempDirectory("keystore").toFile().getAbsolutePath()
				+ "test-keystore.jks";
		Path keystorePath = Path.of(keystoreFile);
		
		App app = new App();

		// First, run with self-signed cert	
		app.run(new String[] 
				{"-key", privKeyFile, 
				 "-chain", chainFile, 
				 "-out", keystoreFile});
		
		assertTrue(keystorePath.toFile().exists(), "Keystore was not created!");
		ks = app.loadKeyStore(App.DEFAULT_KEYSTORE_PASSWORD, keystorePath.toUri().toURL());
		for (Enumeration<String> aliases = ks.aliases(); aliases.hasMoreElements();) {
			System.err.println(aliases.nextElement());
		}

		assertTrue(ks.containsAlias(selfSignedCertCN), "Keystore has no entry for: " + selfSignedCertCN + "!");

		assertTrue(ks.isKeyEntry(selfSignedCertCN), "Keystore contains the wrong entry type!");

		keystoreCert = ks.getCertificate(selfSignedCertCN);
		keystorePubKey = keystoreCert.getPublicKey();
		keystoreCert.verify(keystorePubKey);
		
		// Now, replace with the CA-signed cert
		privKeyFile = Path.of(caSignedKeyUrl.toURI()).toAbsolutePath().toString();
		certFile = Path.of(caSignedCertUrl.toURI()).toAbsolutePath().toString();
		chainFile = Path.of(caCertUrl.toURI()).toAbsolutePath().toString();
		app.run(new String[] 
				{"-key", privKeyFile,
				 "-cert", certFile,
				 "-chain", chainFile,
				 "-out", keystoreFile});
		
		assertTrue(keystorePath.toFile().exists(), "Keystore was deleted!");
		// Need to reload to see changes
		ks = app.loadKeyStore(App.DEFAULT_KEYSTORE_PASSWORD, keystorePath.toUri().toURL());
		for (Enumeration<String> aliases = ks.aliases(); aliases.hasMoreElements();) {
			System.err.println(aliases.nextElement());
		}
		assertTrue(ks.containsAlias(caSignedCertCN), "Keystore has no entry for: " + caSignedCertCN + "!");
		assertTrue(ks.isKeyEntry(caSignedCertCN), "Keystore contains the wrong entry type!");
		
		keystoreCert = ks.getCertificate(caSignedCertCN);
	}
	
    @Test
    void testGetCertChainSelfSigned() throws Exception {
		App app = new App();

		List<X509Certificate> certs = app.getCertChain(selfSignedCertUrl);
		assertEquals(1, certs.size());
    }

	@Test
	void testGetPrivateKey() throws Exception {
		App app = new App();

		assertDoesNotThrow(
			() -> app.getPrivateKey(selfSignedKeyUrl),
			"getPrivateKey() should not throw");
	}

	@Test
	void testGetCertCN() throws Exception {
		App app = new App();

		assertEquals(selfSignedCertCN, app.getCertCN(app.getCertChain(selfSignedCertUrl).get(0)));
	}

	@Test
	void testNewSingleEntryKeystore() throws PemToJksException, KeyStoreException {
		App app = new App();
		List<X509Certificate> selfSignedChain = app.getCertChain(selfSignedCertUrl);
		X509Certificate cert = selfSignedChain.get(0);

		KeyStore ks = app.newSingleEntryKeystore(
				app.getPrivateKey(selfSignedKeyUrl),
				cert,
				selfSignedChain,
				App.DEFAULT_KEYSTORE_PASSWORD);
		assertTrue(ks.containsAlias("PemToJksTesting"), "Did not find alias in keystore");
	}
}
