package com.scsi.pemtojks;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.IOException;
import java.util.List;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import org.junit.jupiter.api.Test;

public class AppTest {
    @Test
    void testGetCertChain() throws Exception {
		App app = new App();

		try (InputStream publicKeyIn = this.getClass().getResourceAsStream("rsa_cert.pem");) {
			List<X509Certificate> certs = app.getCertChain(publicKeyIn);
			assertEquals(1, certs.size());
			System.out.println(certs.get(0).getSubjectX500Principal());
		} 
    }

	@Test
	void testGetPrivateKey() throws Exception {
		App app = new App();

		try (InputStream privateKeyIn = this.getClass().getResourceAsStream("rsa_private.pem");) {
			assertDoesNotThrow(
				() -> app.getPrivateKey(privateKeyIn),
				"getPrivateKey() should not throw");
		}
	}

	@Test
	void testGetCertCN() throws Exception {
		App app = new App();

		try (InputStream publicKeyIn = this.getClass().getResourceAsStream("rsa_cert.pem");) {
			assertEquals("PemToJksTesting", app.getCertCN(app.getCertChain(publicKeyIn).get(0)));
		} 
	}

	@Test
	void testNewSingleEntryKeystore() throws Exception {
		App app = new App();

		try (InputStream publicKeyIn = this.getClass().getResourceAsStream("rsa_cert.pem");
			 InputStream privateKeyIn = this.getClass().getResourceAsStream("rsa_private.pem");) {
			KeyStore ks = app.newSingleEntryKeystore(
					app.getPrivateKey(privateKeyIn),
					app.getCertChain(publicKeyIn));
			assertTrue(ks.containsAlias("PemToJksTesting"), "Did not find alias in keystore");
		 }
	}
}
