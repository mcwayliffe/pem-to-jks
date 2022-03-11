package com.scsi.pemtojks;

import java.io.BufferedInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.converters.PathConverter;


// TODO
// 1. Load an existing keystore.
// 2. Delete the alias from that keystore if it exists (but ONLY if we're 100% sure we can replace it)
// 3. Test this on a running instance of Apache-FTPServer
public class App {
	private static final Pattern CN_PAT_RFC1779 = Pattern.compile("CN\\s*=\\s*([A-Za-z0-9._ -]+)(,)*");
	private static final String DEFAULT_KEYSTORE_NAME = "keystore";
	static final String DEFAULT_KEYSTORE_PASSWORD = "changeit";
	
	@Parameter(names = "-help", help = true)
	private boolean help;
	
	@Parameter(names = "-force")
	private boolean overwriteExistingKeystore;
	
	@Parameter(names = "-verbose")
	private boolean verbose;

	@Parameter(names = "-key", converter = PathConverter.class, required = true)
	private Path keyFile;

	@Parameter(names = "-keypass")
	private String keyPass = "";

	@Parameter(names = "-cert", converter = PathConverter.class)
	private Path certFile;

	@Parameter(names = "-chain", converter = PathConverter.class, required = true)
	private Path chainFile; // Assume the cert is the first one if no cert file

	@Parameter(names = "-out", converter = PathConverter.class)
	private Path keystoreFile = Path.of(DEFAULT_KEYSTORE_NAME); // Make sure this ends with ".jks"

	@Parameter(names = "-storepass")
	private String storePass = DEFAULT_KEYSTORE_PASSWORD;

	@Parameter(names = "-alias")
	private String alias = ""; // Will use the CN from the cert if none specified
	
	@Parameter(names = "-storetype")
	private String storeType = KeyStore.getDefaultType();
	
    public static void main(String[] args) throws PemToJksException {
		new App().run(args);
    }
    
    
    public void run(String[] args) throws PemToJksException {
    	List<X509Certificate> certChain;
    	X509Certificate clientCert;

		initializeArgs(args);
		
		if (this.keystoreFile.toFile().exists()) {
			if (!this.overwriteExistingKeystore) {
				throw new PemToJksException("ERROR: file " + this.keyFile + " exists. Use '-force' to overwrite");
			} else if (this.verbose){
				System.out.println("INFO: file " + this.keyFile + " exists -- will overwrite it");
			}
		}
    	
    	certChain = getCertChain(pathToUrl(this.chainFile));
		if (certChain.isEmpty()) {
			throw new PemToJksException("ERROR: No certificates found in chain file");
		}
		if (this.verbose) {
			System.out.println("INFO: === CHAIN ===");
			logCertChain(certChain);
		}

		clientCert = (null != this.certFile) ? 
				getSingleCert(pathToUrl(this.certFile)) 
				: certChain.get(0);
		
		if (this.verbose) {
			System.out.println("INFO: === CLIENT CERT ===");
			logCertInfo(clientCert);
		}
		
		throwIfCertWontValidate(clientCert); // Expiration
		throwIfCertWontVerify(clientCert, certChain); // Signatures 
		
		RSAPrivateKey privateKey = getPrivateKey(pathToUrl(this.keyFile));
		KeyStore keystore = newSingleEntryKeystore(privateKey, clientCert, certChain);
		
		saveKeyStore(keystore, this.storePass, this.keystoreFile);
    }
    

    void initializeArgs(String[] args) {
		JCommander jc = JCommander.newBuilder()
				.addObject(this)
				.build();
		
		try {
			jc.parse(args);
		} catch (ParameterException e) {
			jc.usage();
			System.exit(1);
		}

		if (this.help) {
			jc.usage();
			System.exit(1);
		}
		
		// We want the key password to default to the store password if the user passes one in
		if ("".equals(this.keyPass)) {
			this.keyPass = this.storePass;
		}
		
		switch (this.storeType) {
		case "JKS":
			
		}
    }
    
    
    X509Certificate getSingleCert(URL certUrl) throws PemToJksException {
		List<X509Certificate> certs = getCertChain(certUrl);
			
		if (1 != certs.size()) {
			throw new PemToJksException(
					"ERROR: [" + certUrl + "] must contain one and only one certificate.");
		}
    		
		return certs.get(0);
    }
    
    
	List<X509Certificate> getCertChain(URL certUrl) throws PemToJksException {
		List<X509Certificate> certs = new ArrayList<>();
		Certificate nextCert;
		CertificateFactory cf;

		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new PemToJksException(
					"Could not get a CertificateFactory for X509 format " + e.getMessage(), e);
		}

		try (BufferedInputStream bis = new BufferedInputStream(certUrl.openStream());) {
			while (bis.available() > 0) {
				nextCert = cf.generateCertificate(bis);
				if (nextCert instanceof X509Certificate) {
					certs.add((X509Certificate) nextCert);
					if (this.verbose) {
						System.out.println("INFO: === In " + certUrl + " ===");
						System.out.println(nextCert);
					}
				} else {
					throw new PemToJksException("Found a cert of an unexpected type: " + nextCert.getType());
				}
			}
		} catch (IOException | CertificateException e) {
			throw new PemToJksException(
					"Could not parse cert chain from URL (" + certUrl + "): " + e.getMessage(), e);
		}

		return certs;
	}
	
	
    void throwIfCertWontValidate(X509Certificate cert) throws PemToJksException {
    	if (this.verbose) {
    		System.out.println("INFO: Checking cert " + cert.getSubjectX500Principal() + " for validity");
    	}

		try {
			cert.checkValidity();
		} catch (CertificateExpiredException e) {
			throw new PemToJksException("ERROR: Certificate has expired " + e.getMessage());
		} catch (CertificateNotYetValidException e) {
			throw new PemToJksException("ERROR: Certificate is not yet valid " + e.getMessage());
		}
    }
    
    
    void throwIfCertWontVerify(X509Certificate cert, List<X509Certificate> chain) throws PemToJksException {
		X509Certificate curCert = cert;
		
		for (X509Certificate intermediate : chain) {
			if (this.verbose) {
				System.out.println("INFO: Verifying " + curCert.getSubjectX500Principal() + " against " + intermediate.getSubjectX500Principal());
			}
			try {
				curCert.verify(intermediate.getPublicKey());
				if (this.verbose) {
					System.out.println("INFO: Verified successfully");
				}
			} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException
					| SignatureException e) {
				throw new PemToJksException("Could not validate certificate: " + e.getMessage(), e);
			}
			curCert = intermediate;
		}
    }
    
    
	KeyStore newSingleEntryKeystore(RSAPrivateKey key, X509Certificate cert, List<X509Certificate> chain) 
			throws PemToJksException {
		KeyStore store;
		List<X509Certificate> fullChain;
		
		if (cert == null) {
			throw new PemToJksException("ERROR: No client certificate given");
		}
		
		if (chain == null || chain.isEmpty()) {
			throw new PemToJksException("ERROR: The certificate chain is empty");
		}
		
		fullChain = new ArrayList<>(chain);
		fullChain.add(0, cert);
		
		store = createEmptyKeyStore(this.storePass);

		String entryAlias = ! "".equals(this.alias) ? this.alias : getCertCN(cert);

		if ("".equals(entryAlias)) {
			throw new PemToJksException(
					"Could not store entry: no alias provided AND the certificate has no /CN field");
		} 

		try {
			store.setKeyEntry(entryAlias, key, this.keyPass.toCharArray(), chain.toArray(new Certificate[chain.size()]));
		} catch (KeyStoreException e) {
			throw new PemToJksException("Could not store entry in keystore: " + e.getMessage(), e);
		}

		return store;
	}
    
    
    KeyStore createEmptyKeyStore(String ksPass) throws PemToJksException {
    	return loadKeyStore(ksPass, null);
    }
    
    
    KeyStore loadKeyStore(String ksPass, URL ksUrl) throws PemToJksException {
    	KeyStore ks;
		String initializeErr = "Could not initialize keystore of type " + this.storeType + ": ";

    	try {
    		ks = KeyStore.getInstance(this.storeType);
    	} catch (KeyStoreException e) {
			throw new PemToJksException(initializeErr + e.getMessage(), e);
    	}

    	if (null == ksUrl) { // Load an empty keystore
			try {
				ks.load(null, ksPass.toCharArray());
			} catch (NoSuchAlgorithmException | CertificateException | IOException e) {
				throw new PemToJksException(initializeErr + e.getMessage(), e);
			}
    	} else { // Load an existing keystore
    		try (InputStream ksIn = ksUrl.openStream();) {
    			ks.load(ksIn, ksPass.toCharArray());
			} catch (NoSuchAlgorithmException | CertificateException | IOException e) {
				throw new PemToJksException(initializeErr + e.getMessage(), e);
			}
    	}
    	
    	return ks;
    }
    
    
    void saveKeyStore(KeyStore ks, String ksPass, Path ksPath) throws PemToJksException {
    	try (FileOutputStream ksOut = new FileOutputStream(ksPath.toFile());) {
    		ks.store(ksOut, ksPass.toCharArray());
    	} catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
    		throw new PemToJksException(
    				"Could not write keystore file (" 
					+ ksPath.toAbsolutePath() + "): " 
					+ e.getMessage(), e);
    	}
    }
    
    
	RSAPrivateKey getPrivateKey(URL keyUrl) throws PemToJksException {
		KeyFactory kf;

		try {
			kf = KeyFactory.getInstance("RSA"); // This is *probably* a safe assumption
		} catch (NoSuchAlgorithmException e) {
			throw new PemToJksException("Could not get a KeyFactory for algorithm RSA " + e.getMessage(), e);
		} 

		try {
			String keyData = new String(keyUrl.openStream().readAllBytes())
					.replaceAll("-----BEGIN PRIVATE KEY-----", "")
					.replaceAll(System.lineSeparator(), "")
					.replaceAll("-----END PRIVATE KEY-----", "");

			if (keyData.contains("-")) { // This means we didn't strip off the header and footer
				throw new PemToJksException("ERROR: Private Key is not in PKCS#8 format");
			}

			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(keyData));
			return (RSAPrivateKey) kf.generatePrivate(keySpec);
		} catch (IOException | InvalidKeySpecException e) {
			throw new PemToJksException("Could not read private key: " + e.getMessage(), e);
		}
	}
		

	String getCertCN(X509Certificate cert) {
		X500Principal principal = cert.getSubjectX500Principal();
		String distinguishedName = principal.getName(X500Principal.RFC1779);
		Matcher match = CN_PAT_RFC1779.matcher(distinguishedName);
		
		return match.find() ? match.group(1) : "";
	}
	
	
	URL pathToUrl(Path path) throws PemToJksException {
		Path absPath = path.toAbsolutePath();

		try {
			return absPath.toUri().toURL();
		} catch (MalformedURLException e) {
			throw new PemToJksException(
					"Could not locate path (" + absPath + "): " + e.getMessage(), e);
		}
	}
	
	// Logging helpers
	void logCertChain(List<X509Certificate> chain) throws PemToJksException {
		for (X509Certificate cert : chain) {
			logCertInfo(cert);
		}
	}
	
	
	void logCertInfo(X509Certificate cert) throws PemToJksException {
		if (this.verbose) {
			X500Principal sub = cert.getSubjectX500Principal();
			X500Principal issuer = cert.getIssuerX500Principal();

			// TODO It would be nice to have the Fingerprint output here
			System.out.println("INFO: Subject: " +  sub);
			System.out.println("INFO: Issuer: " + issuer);
		}
	}

	// Setters for testing
	void setKeyPass(String pass) {
		this.keyPass = pass;
	}
	

	void setStorePass(String pass) {
		this.storePass = pass;
	}
}