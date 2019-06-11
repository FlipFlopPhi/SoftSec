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

import javax.smartcardio.CardException;
import javax.smartcardio.TerminalFactory;

import terminal.exception.CardBlockedException;
import terminal.exception.FailedPersonalizationException;
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
		}*/
		try {
			Personalizer.personalize();
		} catch (FailedPersonalizationException e1) {
			System.err.println("Personalization failed \n"+e1.getLocalizedMessage());
			e1.printStackTrace();
			return;
		}
		try {
			TerminalWithPin terminal = new Charger();
			while(TerminalFactory.getDefault().terminals().list().size() == 0) {}
			try {
				
				terminal.initCommunications();
			} catch (IncorrectSequenceNumberException | GeneralSecurityException | IncorrectResponseCodeException
					| CardBlockedException | IncorrectCertificateException e) {
				e.printStackTrace();
			}
		} catch (Exception e) {e.printStackTrace();}
	}

}
