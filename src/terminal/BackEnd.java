/**
 * 
 */
package terminal;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import terminal.util.Util;

/**
 * @author pspaendonck
 * The magical Back End that will take care of everything!
 */
public class BackEnd {

	private final static BackEnd instance = new BackEnd();
	
	private final Map<Integer,PublicKey> cardKeys;
	private final Map<Integer, Account> cardHolders;
	private final PublicKey publicM;
	private final PrivateKey privateM;
	
	private BackEnd() {
		cardKeys = new HashMap<Integer, PublicKey>();
		cardHolders = new HashMap<Integer, Account>();
		KeyPairGenerator generator;
		KeyPair kp = null;
		try {
			generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(Util.KEY_LENGTH * 8);
			kp = generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			System.err.println("RSA key pair generator could not be set up.");
			e.printStackTrace();
		}
		publicM = kp.getPublic();
		privateM = kp.getPrivate();
	}
	
	public final static BackEnd getInstance() {return instance;}

	/**
	 * This method should encrypt the information using the masterkey
	 * @param array
	 * @return
	 * @throws GeneralSecurityException 
	 */
	public byte[] requestMasterEncryption(byte[] array) throws GeneralSecurityException {
		return Util.encrypt(privateM, array);
	}
	
	public RSAPublicKey getPublicMasterKey() {
		return (RSAPublicKey) publicM;
	}

	public void storeCardInfo(int cardNumber, PublicKey publicC) {
		cardKeys.put(Integer.valueOf(cardNumber), publicC);
	}
	
	public void registerCard(int cardNumber, Account account) {
		cardHolders.put(Integer.valueOf(cardNumber), account);
	}
	
	public Account getAccount(int cardNumber) {
		return cardHolders.get(Integer.valueOf(cardNumber));
	}
	
}
