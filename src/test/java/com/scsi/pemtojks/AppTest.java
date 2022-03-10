package com.scsi.pemtojks;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.IOException;
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
	private final String certCN = "PemToJksTesting";
	
	@Test
	void testMain() throws Exception {
		String privKeyFile = Path.of(selfSignedKeyUrl.toURI()).toAbsolutePath().toString();
		String chainFile = Path.of(selfSignedCertUrl.toURI()).toAbsolutePath().toString();
		String keystoreFile = Files.createTempDirectory("keystore").toFile().getAbsolutePath()
				+ "test-keystore.jks";
		Path keystorePath = Path.of(keystoreFile);

			
		App.main(new String[] 
				{"-key", privKeyFile, 
				 "-chain", chainFile, 
				 "-out", keystoreFile});
		
		assertTrue(keystorePath.toFile().exists(), "Keystore was not created!");

		KeyStore ks = App.loadKeyStore(App.DEFAULT_KEYSTORE_PASSWORD, keystorePath.toUri().toURL());
		ks.isKeyEntry(certCN);

		Certificate selfSignedCert = ks.getCertificate(certCN);
		PublicKey pubKey = selfSignedCert.getPublicKey();
		selfSignedCert.verify(pubKey);
	}
	
    @Test
    void testGetCertChain() throws Exception {
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

		assertEquals(certCN, app.getCertCN(app.getCertChain(selfSignedCertUrl).get(0)));
	}

	@Test
	void testNewSingleEntryKeystore() throws PemToJksException, KeyStoreException {
		App app = new App();

		KeyStore ks = app.newSingleEntryKeystore(
				app.getPrivateKey(selfSignedKeyUrl),
				app.getCertChain(selfSignedCertUrl),
				App.DEFAULT_KEYSTORE_PASSWORD);
		assertTrue(ks.containsAlias("PemToJksTesting"), "Did not find alias in keystore");
	}
}
