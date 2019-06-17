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
import java.security.PublicKey;
import java.security.spec.RSAKeyGenParameterSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
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
		try {
			Personalizer.personalize();
		} catch (FailedPersonalizationException e1) {
			System.err.println("Personalization failed \n" + e1.getLocalizedMessage());
			e1.printStackTrace();
			return;
		}
		try {
			TerminalWithPin terminal = new Charger();
			while (TerminalFactory.getDefault().terminals().list().size() == 0) {
			}
			try {

				terminal.initCommunications();
			} catch (IncorrectSequenceNumberException | GeneralSecurityException | IncorrectResponseCodeException
					| CardBlockedException | IncorrectCertificateException e) {
				e.printStackTrace();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
