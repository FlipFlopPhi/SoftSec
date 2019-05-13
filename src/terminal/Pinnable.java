/**
 * 
 */
package terminal;

/**
 * @author pspaendonck
 *
 */
public interface Pinnable {
	
	public byte[] enterPin() throws InvalidPinException;

	public void showSucces();

	public void showFailed();

	public void showBlocked();
}
