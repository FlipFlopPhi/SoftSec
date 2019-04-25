/**
 * 
 */
package terminal.exception;

/**
 * @author pspaendonck
 *
 */
public class IncorrectResponseCodeException extends Exception {

	public IncorrectResponseCodeException(byte code) {
		super("An incorrect response code was recieved: " + code);
	}
}
