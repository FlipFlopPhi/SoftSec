/**
 * 
 */
package terminal;

/**
 * @author pspaendonck
 *
 */
public class InvalidPinException extends Exception {

	public InvalidPinException(int pin) {
		super("An incorrect PIN was entered: "+pin);
	}
}
