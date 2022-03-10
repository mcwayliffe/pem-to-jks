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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
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
import com.beust.jcommander.converters.PathConverter;


// TODO
// 1. Load an existing keystore.
// 2. Delete the alias from that keystore if it exists (but ONLY if we're 100% sure we can replace it)
// 3. Test this on a running instance of Apache-FTPServer
public class App {
	private static final Pattern CN_PAT_RFC1779 = Pattern.compile("CN\\s*=\\s*([A-Za-z0-9._-]+)(,)*");
	private static final String DEFAULT_KEYSTORE_NAME = "keystore.jks";
	static final String DEFAULT_KEYSTORE_PASSWORD = "changeit";

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
	private String keystorePass = DEFAULT_KEYSTORE_PASSWORD;

	@Parameter(names = "-alias")
	private String alias = ""; // Will use the CN from the cert if none specified


	
    public static void main( String[] args ) throws PemToJksException {
		App app = new App();

		JCommander.newBuilder()
				.addObject(app)
				.build()
				.parse(args);
		
		app.run();
    }
    
    
    /**
     * **IMPORTANT** This method assumes that arguments have been set on "this"
     * @throws CertificateException 
     * @throws InvalidKeySpecException 
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     * @throws PemToJksException 
     */
    public void run() throws PemToJksException {
    	List<X509Certificate> completeCertChain = new ArrayList<>();
    	X509Certificate clientCert = null;

    	if (null != this.certFile) { // They've given us both a cert and a chain
			completeCertChain.addAll(getCertChain(pathToUrl(this.certFile)));
    		if (1 != completeCertChain.size()) {
    			// TODO
    			throw new PemToJksException("ERROR: The certificate file [" 
    			                           + this.certFile.toAbsolutePath()
    			                           + "] must contain one and only one certificate.");
    		}
    		
    		clientCert = completeCertChain.get(0);
    	}
    	
		completeCertChain.addAll(getCertChain(pathToUrl(this.chainFile)));
		
		if (completeCertChain.isEmpty()) {
			// TODO
			throw new PemToJksException("ERROR: No certificates found in chain file");
		}
		
		if (null == clientCert) {
			clientCert = completeCertChain.get(0);
		}
		
		try {
			clientCert.checkValidity();
		} catch (CertificateExpiredException e) {
			throw new PemToJksException("ERROR: Certificate has expired " + e.getMessage());
		} catch (CertificateNotYetValidException e) {
			throw new PemToJksException("ERROR: Certificate is not yet valid " + e.getMessage());
		}
		
		X509Certificate curCert = clientCert;
		
		for (X509Certificate intermediate : completeCertChain) {
			try {
				curCert.verify(intermediate.getPublicKey());
			} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException
					| SignatureException e) {
				// TODO Auto-generated catch block
				throw new PemToJksException("Could not validate certificate: " + e.getMessage());
			}
		}
		
		RSAPrivateKey privateKey = getPrivateKey(pathToUrl(this.keyFile));
		KeyStore keystore = newSingleEntryKeystore(privateKey, completeCertChain, keystorePass);
		saveKeyStore(keystore, this.keystorePass, this.keystoreFile);
    }
    
    
    KeyStore createEmptyKeyStore(String ksPass) throws PemToJksException {
    	return loadKeyStore(ksPass, null);
    }
    
    
    static KeyStore loadKeyStore(String ksPass, URL ksUrl) throws PemToJksException {
    	KeyStore ks;
		String ksType = KeyStore.getDefaultType();
		String initializeErr = "Could not initialize keystore of type " + ksType + ": ";

    	try {
    		ks = KeyStore.getInstance(ksType);
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
    
    
	KeyStore newSingleEntryKeystore(RSAPrivateKey key, List<X509Certificate> chain, String passwd) 
			throws PemToJksException {
		// This method assumes that the first cert in the chain is "our" cert. Is that safe???
		KeyStore store;
		
		if (chain == null || chain.isEmpty()) {
			throw new PemToJksException("ERROR: The certificate chain is empty");
		}
		
		store = createEmptyKeyStore(passwd);

		String entryAlias = determineEntryAlias(chain.get(0));

		if ("".equals(entryAlias)) {
			// TODO
			throw new PemToJksException(
					"Could not store entry: no alias argument given AND the certificate has no /CN field");
		} 

		try {
			store.setKeyEntry(entryAlias, key, passwd.toCharArray(), chain.toArray(new Certificate[chain.size()]));
		} catch (KeyStoreException e) {
			throw new PemToJksException("Could not store entry in keystore: " + e.getMessage(), e);
		}

		return store;
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
					.replace("-----BEGIN PRIVATE KEY-----", "")
					.replaceAll(System.lineSeparator(), "")
					.replace("-----END PRIVATE KEY-----", "");
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(keyData));
			return (RSAPrivateKey) kf.generatePrivate(keySpec);
		} catch (IOException | InvalidKeySpecException e) {
			throw new PemToJksException("Could not read private key: " + e.getMessage(), e);
		}
	}
		

	List<X509Certificate> getCertChain(URL certUrl) throws PemToJksException {
		List<X509Certificate> certs = new ArrayList<>();
		Certificate nextCert;
		CertificateFactory cf;

		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new PemToJksException("Could not get a CertificateFactory for X509 format " + e.getMessage(), e);
		}

		try (BufferedInputStream bis = new BufferedInputStream(certUrl.openStream());) {
			while (bis.available() > 0) {
				nextCert = cf.generateCertificate(bis);
				if (nextCert instanceof X509Certificate) {
					certs.add((X509Certificate) nextCert);
				} else {
					System.err.println("Found a cert of an unexpected type: " + nextCert.getType());
				}
			}
		} catch (IOException | CertificateException e) {
			throw new PemToJksException("Could not parse cert chain from URL (" + certUrl + "): " + e.getMessage(), e);
		}

		return certs;
	}
	
	
	String determineEntryAlias(X509Certificate cert) {
		return ! "".equals(this.alias) ? this.alias : getCertCN(cert);
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
}