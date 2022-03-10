package com.scsi.pemtojks;

public class PemToJksException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 7767083374455367094L; 
	
	public PemToJksException(String msg) {
		super(msg);
	}
	
	public PemToJksException(String msg, Throwable cause) {
		super(msg, cause);
	}
}