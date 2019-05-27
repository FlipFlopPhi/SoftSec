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
		System.out.println("whaat?:"+ BackEnd.getInstance().requestMasterEncryption(new byte[] {1}).length);
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
