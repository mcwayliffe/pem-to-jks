package com.scsi.pemtojks;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class AppTest {
	private static final URL SELF_SIGNED_CERT_URL = AppTest.class.getResource("self_signed_site_cert.pem");
	private static final URL SELF_SIGNED_KEY_URL = AppTest.class.getResource("self_signed_site_priv.pem");
	private static final URL CA_SIGNED_CERT_URL = AppTest.class.getResource("ca_signed_site_cert.pem");
	private static final URL CA_SIGNED_CERT_FULL_CHAIN_URL = AppTest.class.getResource("ca_signed_site_full_chain.pem");
	private static final URL CA_CERT_URL = AppTest.class.getResource("ca/dummy_root_ca_cert.pem");
	private static final URL CA_SIGNED_KEY_URL = AppTest.class.getResource("ca_signed_site_priv.pem");
	private static final String SELF_SIGNED_CERT_CN = "PemToJksTesting";
	private static final String CA_SIGNED_CERT_CN = "PemToJks CA-Signed Cert";
	
	private static class ChainInfo {
		URL key, cert, chain;
		String cn;
		int chainLen;
		
		public ChainInfo(URL key, URL cert, URL chain, String cn, int len) {
			this.key = key;
			this.cert = cert;
			this.chain = chain;
			this.cn = cn;
			this.chainLen = len;
		}
		
		public String toString() {
			return "CN: [" + cn + "]\nCert: [" + cert + "]\nKey: [" + key + "]\nChain: [" + chain + "]";
		}
	}
	
	@ParameterizedTest
	@MethodSource("chainInfoProvider")
	void testMain(AppTest.ChainInfo chainInfo) throws Exception {
		final Random random = new Random();
		final String privKeyFile = Path.of(chainInfo.key.toURI()).toAbsolutePath().toString();
		final String chainFile = Path.of(chainInfo.chain.toURI()).toAbsolutePath().toString();
		final String keystoreFile = Files.createTempDirectory("keystore").toFile().getAbsolutePath()
				+ random.nextInt(1000) + ".jks";
		final Path keystorePath = Path.of(keystoreFile);
		final String storePassOverride = "verysecure";
		final String keyPassOverride = "alsoprettysecure";
		final App app = new App();
		KeyStore ks;

		app.run(new String[] 
				{"-key", privKeyFile, 
				 "-chain", chainFile, 
				 "-out", keystoreFile, 
				 "-storepass", storePassOverride, 
				 "-storetype", "JKS",
				 "-keypass", keyPassOverride});

		assertTrue(keystorePath.toFile().exists(), "Keystore was not created!");

		ks = app.loadKeyStore(storePassOverride, keystorePath.toUri().toURL());
		assertTrue(ks.containsAlias(chainInfo.cn), "Keystore has no entry for: " + chainInfo.cn + "!");
		assertTrue(ks.isKeyEntry(chainInfo.cn), "Keystore contains the wrong entry type!");
		{ 
			Certificate storedCert = ks.getCertificate(chainInfo.cn);
			Certificate[] storedChain = ks.getCertificateChain(chainInfo.cn);
			PublicKey storedPubKey = storedCert.getPublicKey();
			Certificate nextCert;

			assertEquals(chainInfo.chainLen, storedChain.length);
			
			for (int i = 1; i < storedChain.length; i++) {
				nextCert = storedChain[i];
				// This will throw if something is wrong
				storedCert.verify(nextCert.getPublicKey());
				storedCert = nextCert;
			}

			// Will throw if the key is improperly stored
			ks.getKey(chainInfo.cn, keyPassOverride.toCharArray());
		}
	}
	
	@ParameterizedTest
	@MethodSource("chainInfoProvider")
    void testGetCertChain(AppTest.ChainInfo chainInfo) throws Exception {
		App app = new App();
		assertEquals(chainInfo.chainLen, app.getCertChain(chainInfo.chain).size());
    }

	@ParameterizedTest
	@MethodSource("chainInfoProvider")
	void testGetPrivateKey(AppTest.ChainInfo chainInfo) throws Exception {
		App app = new App();
		assertDoesNotThrow(
			() -> app.getPrivateKey(chainInfo.key),
			"getPrivateKey() should not throw");
	}

	@ParameterizedTest
	@MethodSource("chainInfoProvider")
	void testGetCertCN(AppTest.ChainInfo chainInfo) throws Exception {
		App app = new App();
		assertEquals(chainInfo.cn, app.getCertCN(app.getSingleCert(chainInfo.cert)));
	}

	@ParameterizedTest
	@MethodSource("chainInfoProvider")
	void testNewSingleEntryKeystore(AppTest.ChainInfo chainInfo) throws PemToJksException, KeyStoreException {
		App app = new App();
		app.setKeyPass(App.DEFAULT_KEYSTORE_PASSWORD);
		List<X509Certificate> chain = app.getCertChain(chainInfo.chain);
		X509Certificate cert = chain.get(0); 
		
		KeyStore ks = app.newSingleEntryKeystore(app.getPrivateKey(chainInfo.key), cert, chain);
		assertTrue(ks.containsAlias(chainInfo.cn), "Did not find alias in keystore");
		assertEquals(1, ks.size());
	}
	
	static Stream<AppTest.ChainInfo> chainInfoProvider() {
		return Stream.of(
				new AppTest.ChainInfo(SELF_SIGNED_KEY_URL, SELF_SIGNED_CERT_URL, SELF_SIGNED_CERT_URL, SELF_SIGNED_CERT_CN, 1),
				new AppTest.ChainInfo(CA_SIGNED_KEY_URL, CA_SIGNED_CERT_URL, CA_SIGNED_CERT_FULL_CHAIN_URL, CA_SIGNED_CERT_CN, 2));
	}
}
