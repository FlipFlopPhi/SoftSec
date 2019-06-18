/**
 * 
 */
package terminal;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author Vizu
 * The interface for the back-end
 */
public interface IBackEnd {
	
	/**
	 * Retrieves the RSA public master key from the back-end
	 */
	public RSAPublicKey getPublicMasterKey();
	
	/**
	 * Store the cardInfo on the back-end.
	 */
	public void storeCardInfo(int cardNumber, PublicKey publicC);
	
	/**
	 * Register a card owner's user's credentials on the back-end.
	 */
	public void registerCard(int cardNumber, Account account);
	
	/**
	 * Retrieves a card's cardOwner's account.
	 */
	public Account getAccount(int cardNumber);
	
	/**
	 * Creates a master certificate containing the submitted publicKey
	 */
	public byte[] requestCertificate(RSAPublicKey publicKey) throws GeneralSecurityException;

}
