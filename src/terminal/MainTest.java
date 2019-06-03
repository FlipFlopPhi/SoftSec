/**
 * 
 */
package terminal;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.RSAKeyGenParameterSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.smartcardio.CardException;
import javax.smartcardio.TerminalFactory;

import terminal.exception.CardBlockedException;
import terminal.exception.IncorrectCertificateException;
import terminal.exception.IncorrectResponseCodeException;
import terminal.exception.IncorrectSequenceNumberException;
import terminal.util.Util;

/**
 * @author pspaendonck
 *
 */
public class MainTest {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		byte[] testArray = new byte[17];
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
		}
		
		/*try {
			System.out.println("whaat?:"+ BackEnd.getInstance().requestMasterEncryption(new byte[] {1}).length);
			TerminalWithPin terminal = new Charger();
			while(TerminalFactory.getDefault().terminals().list().size() == 0) {}
			try {
				terminal.initCommunications();
			} catch (IncorrectSequenceNumberException | GeneralSecurityException | IncorrectResponseCodeException
					| CardBlockedException | IncorrectCertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CardException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		*/
	}

}
