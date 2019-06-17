/**
 * 
 */
package terminal;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author Vizu
 *
 */
public interface IBackEnd {
	
	public RSAPublicKey getPublicMasterKey();
	public void storeCardInfo(int cardNumber, PublicKey publicC);
	public void registerCard(int cardNumber, Account account);
	public Account getAccount(int cardNumber);
	public byte[] requestCertificate(RSAPublicKey publicKey) throws GeneralSecurityException;

}
