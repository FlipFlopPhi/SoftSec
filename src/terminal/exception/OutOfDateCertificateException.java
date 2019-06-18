/**
 * 
 */
package terminal.exception;

import terminal.util.BytesHelper;

/**
 * @author Vizu
 *
 */
public class OutOfDateCertificateException extends Exception {

	public OutOfDateCertificateException(byte[] now, byte[] certDate) {
		super("Certificate is out of date.\n Current date:"
				+BytesHelper.toDate(now)+"\n Certificate Expiration Date: " + BytesHelper.toDate(certDate));
	}
}
