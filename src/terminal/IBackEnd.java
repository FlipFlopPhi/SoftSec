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
	 * @param XNumber the card- or terminalnumber to be included into the certificate
	 */
	public byte[] requestCertificate(RSAPublicKey publicKey, int XNumber) throws GeneralSecurityException;

}
