/**
 * 
 */
package terminal.exception;

/**
 * @author pspaendonck
 *
 */
public class IncorrectCertificateException extends Exception {

	public IncorrectCertificateException(byte[] certificate, byte[] decryptedCert) {
		super("Certificate didn't match expectations.");
	}

	
}
