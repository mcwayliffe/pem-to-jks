package com.scsi.pemtojks;

public class Args {
	private String privateKeyFile, privateKeyPass, certFile, chainFile, keystoreOutputFile, keystorePass, keystoreEntryPass;
	

	public static Args parse(String[] args) {
		Iterator<String> i = () -> Arrays.stream(args).iterator();

		return new Args();
	}

	private Args() { }
}
