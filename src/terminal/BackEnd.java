/**
 * 
 */
package terminal;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

import terminal.util.ByteBuilder;
import terminal.util.BytesHelper;
import terminal.util.Util;

/**
 * @author pspaendonck The magical Back End that will take care of everything!
 */
public class BackEnd implements IBackEnd {

	private final static IBackEnd instance = new BackEnd();

	private final static String CARDKEYSFIELDNAME = "cardKeysMap";
	private Map<Integer, PublicKey> cardKeys;
	private final static String CARDHOLDERSFIELDNAME = "cardHoldersMap";
	private Map<Integer, Account> cardHolders;

	private final static String KEYPAIRFIELDNAME = "masterKeyPair";
	private final PublicKey publicM;
	private final PrivateKey privateM;

	/**
	 * @author https://stackoverflow.com/a/15620046
	 * @param fieldName
	 * @param fieldValue
	 * @throws IOException
	 */
	private static void saveField(String fieldName, Object fieldValue) throws IOException {
		FileOutputStream fos = new FileOutputStream(new File("MyClass-" + fieldName + ".dat"));
		ObjectOutputStream oos = new ObjectOutputStream(fos);
		oos.writeObject(fieldValue);
		oos.close();
	}

	/**
	 * @author https://stackoverflow.com/a/15620046
	 * @param fieldName
	 * @return
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	private static Object readField(String fieldName) throws IOException, ClassNotFoundException {
		FileInputStream fis = new FileInputStream(new File("MyClass-" + fieldName + ".dat"));
		ObjectInputStream ois = new ObjectInputStream(fis);
		Object value = ois.readObject();
		ois.close();

		return value;
	}

	@SuppressWarnings("unchecked")
	private BackEnd() {
		try {
			cardKeys = (Map<Integer, PublicKey>) readField(CARDKEYSFIELDNAME);
		} catch (ClassNotFoundException | IOException e1) {
			System.err.println(CARDKEYSFIELDNAME + " could not be found, things might get groovy");
			cardKeys = new HashMap<Integer, PublicKey>();
			try {
				saveField(CARDKEYSFIELDNAME, cardKeys);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		try {
			cardHolders = (Map<Integer, Account>) readField(CARDHOLDERSFIELDNAME);
		} catch (ClassNotFoundException | IOException e1) {
			System.err.println(CARDHOLDERSFIELDNAME + " could not be found, things might get groovy");
			cardHolders = new HashMap<Integer, Account>();
			try {
				saveField(CARDHOLDERSFIELDNAME, cardHolders);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		KeyPair kp = null;
		try {
			kp = (KeyPair) readField(KEYPAIRFIELDNAME);

		} catch (ClassNotFoundException | IOException e1) {
			System.err.println(KEYPAIRFIELDNAME + " could not be found, things might get groovy");
			try {
				KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
				generator.initialize(new RSAKeyGenParameterSpec(Util.MODULUS_LENGTH * 8, BigInteger.valueOf(65537)));
				kp = generator.generateKeyPair();
			} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
				System.err.println("RSA key pair generator could not be set up.");
				e.printStackTrace();
			}
		}
		publicM = kp.getPublic();
		privateM = kp.getPrivate();
		
		if (kp != null) {
			try {
				saveField(KEYPAIRFIELDNAME, kp);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	public final static IBackEnd getInstance() {
		return instance;
	}

	/**
	 * This method should encrypt the information using the masterkey
	 * 
	 * @param array
	 * @return
	 * @throws GeneralSecurityException
	 */
	private byte[] requestMasterEncryption(byte[] array) throws GeneralSecurityException {
		return Util.encrypt(privateM, array);
	}

	public RSAPublicKey getPublicMasterKey() {
		return (RSAPublicKey) publicM;
	}

	public void storeCardInfo(int cardNumber, PublicKey publicC) {
		cardKeys.put(Integer.valueOf(cardNumber), publicC);
		try {
			saveField(CARDKEYSFIELDNAME, cardKeys);
		} catch (IOException e) {
			System.out.println("Card Key could not be stored");
			e.printStackTrace();
		}

	}

	public void registerCard(int cardNumber, Account account) {
		cardHolders.put(Integer.valueOf(cardNumber), account);
		try {
			saveField(CARDHOLDERSFIELDNAME, cardHolders);
		} catch (IOException e) {
			System.out.println("Card Key could not be stored");
			e.printStackTrace();
		}
	}

	public Account getAccount(int cardNumber) {
		return cardHolders.get(Integer.valueOf(cardNumber));
	}

	public byte[] requestCertificate(RSAPublicKey publicKey, int xNumber) throws GeneralSecurityException {
		Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		calendar.add(Calendar.YEAR, 5);
		byte[] date = BytesHelper.fromDate(calendar);
		ByteBuilder hashInput = new ByteBuilder(Util.MODULUS_LENGTH + Util.EXPONENT_LENGTH + Integer.BYTES + 2)
				.addPublicRSAKey(publicKey).add(xNumber).add(date);
		byte[] hash = Util.hash(hashInput.array);
		ByteBuilder certificate = new ByteBuilder(256);
		certificate.add(requestMasterEncryption(Arrays.copyOf(hashInput.array, Util.RSA_BLOCK_LENGTH)));
		byte[] cert2 = Arrays.copyOfRange(hashInput.array, Util.RSA_BLOCK_LENGTH, hashInput.length + 16);
		for (int i = 0; i < 16; i++)
			cert2[11 + 3 + 4 + 2 + i] = hash[i];
		certificate.add(requestMasterEncryption(cert2));
		return certificate.array;
	}

}
