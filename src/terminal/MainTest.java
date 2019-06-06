/**
 * 
 */
package terminal;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import javax.smartcardio.CardException;
import javax.smartcardio.TerminalFactory;

import terminal.exception.CardBlockedException;
import terminal.exception.IncorrectCertificateException;
import terminal.exception.IncorrectResponseCodeException;
import terminal.exception.IncorrectSequenceNumberException;

/**
 * @author pspaendonck
 *
 */
public class MainTest {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		/*byte[] testArray = new byte[17];
		testArray[0] = 5;
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(new RSAKeyGenParameterSpec(Util.MODULUS_LENGTH*8, BigInteger.valueOf(65535)));
			KeyPair kp = generator.generateKeyPair();
			try {
				byte[] intermediate = Util.encrypt(kp.getPrivate(),testArray);
				System.out.println("Whaaat?:" +intermediate.length);
				System.out.println("Okay!:" + Util.decrypt(kp.getPublic(), intermediate).length);
			} catch (GeneralSecurityException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		try {
			KeyGenerator generator = KeyGenerator.getInstance("AES");
			generator.init(Util.AES_KEYSIZE); // advanced Encryption Standard as specified by NIST in FIPS 197.
			SecretKey aesKey = generator.generateKey();
			System.out.println("My dick so long:"+aesKey.getEncoded().length);
			try {
				byte[] intermediate = Util.encrypt(aesKey,"AES", testArray);
				System.out.println("Whaaat?:" +intermediate.length);
				System.out.println("Okay!:" + Util.decrypt(aesKey, "AES", intermediate).length);
			} catch (GeneralSecurityException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
		try {
			Personalizer.personalize();
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (InvalidAlgorithmParameterException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (CardException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		try {
			TerminalWithPin terminal = new Charger();
			while(TerminalFactory.getDefault().terminals().list().size() == 0) {}
			try {
				
				terminal.initCommunications();
			} catch (IncorrectSequenceNumberException | GeneralSecurityException | IncorrectResponseCodeException
					| CardBlockedException | IncorrectCertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (Exception e) {e.printStackTrace();}
	}

}
