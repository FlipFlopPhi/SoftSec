/**
 * 
 */
package terminal.exception;

/**
 * @author Vizu
 *
 */
public class OutOfDateCertificateException extends Exception {

	public OutOfDateCertificateException() {
		super("Certificate is out of date.");
	}
}
