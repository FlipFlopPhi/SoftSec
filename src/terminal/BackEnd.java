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
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

import terminal.util.ByteBuilder;
import terminal.util.BytesHelper;
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

	public byte[] requestCertificate(RSAPublicKey publicKey) throws GeneralSecurityException {
		
		Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		calendar.add(Calendar.YEAR, 5);
		byte[] date = BytesHelper.fromDate(calendar);
		ByteBuilder hashInput = new ByteBuilder(128+3+2).addPublicRSAKey(publicKey).add(date);
		byte[] hash = Util.hash(hashInput.array);
		ByteBuilder certificate = new ByteBuilder(256);
		certificate.add(requestMasterEncryption(Arrays.copyOf(certificate.array, 128)));
		byte[] cert2 = Arrays.copyOfRange(certificate.array, 128, 128 + 3 + 2 + 16);
		for(int i=0; i<16; i++)
			cert2[3 + 2 + i] = hash[i];
		certificate.add(requestMasterEncryption(cert2));
		return certificate.array;
	}
	
}
