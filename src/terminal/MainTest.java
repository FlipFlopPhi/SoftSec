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

	public static byte[] certificateC;
	public static PublicKey publicT;

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		/*byte[] testArray = new byte[128];
		testArray[0] = 5;
		try {
			KeyGenerator generator = KeyGenerator.getInstance("AES");
			generator.init(Util.AES_KEYSIZE); // advanced Encryption Standard as specified by NIST in FIPS 197.
			SecretKey aesKey = generator.generateKey();
			try {
				byte[] intermediate = Util.encryptAES(aesKey,new byte[17]);
				for(byte b : intermediate) {
					System.out.print(b+",");
				}
				System.out.println("Whaaat?:" +intermediate.length);
				System.out.println("Okay!:" + Util.decryptAES(aesKey, intermediate).length);
				for(byte b : Util.decryptAES(aesKey, intermediate)) {
					System.out.print(b+",");
				}
			} catch (GeneralSecurityException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (NoSuchAlgorithmException e1) {
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
