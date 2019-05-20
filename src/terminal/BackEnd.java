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
import java.util.HashMap;
import java.util.Map;

/**
 * @author pspaendonck
 * The magical Back End that will take care of everything!
 */
public class BackEnd {

	private final static BackEnd instance = new BackEnd();
	
	private final Map<Integer,PublicKey> cardKeys;
	private final PublicKey publicM;
	private final PrivateKey privateM;
	
	private BackEnd() {
		cardKeys = new HashMap<Integer, PublicKey>();
		KeyPairGenerator generator;
		KeyPair kp = null;
		try {
			generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(Util.KEY_LENGTH * 8);
			kp = generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		publicM = kp.getPublic();
		privateM = kp.getPrivate();
	}
	
	public static BackEnd getInstance() {return instance;}

	/**
	 * This method should encrypt the information using the masterkey
	 * @param array
	 * @return
	 */
	public byte[] requestMasterEncryption(byte[] array) {
		try {
			return Util.encrypt(privateM, array);
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}
	
	public PublicKey getPublicMasterKey() {
		return publicM;
	}

	public void storeCardInfo(int cardNumber, PublicKey publicC) {
		cardKeys.put(Integer.valueOf(cardNumber), publicC);
	}
	
}
