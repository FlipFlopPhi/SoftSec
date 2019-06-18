/**
 * 
 */
package terminal;

import java.security.GeneralSecurityException;
import java.util.Scanner;

import terminal.exception.CardBlockedException;
import terminal.exception.FailedPersonalizationException;
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
		Scanner scanner = new Scanner(System.in);
		loop: while (true) {
			System.out.println("Personalize? (1), Charger (2), Pump (3), quit (anything else)");
			int choice = scanner.nextInt();
			switch (choice) {
			case 1:
				try {
					Personalizer.personalize();
				} catch (FailedPersonalizationException e1) {
					System.err.println("Personalization failed \n" + e1.getLocalizedMessage());
					e1.printStackTrace();
					return;
				}
				break;

			case 2:
				try {
					TerminalWithPin terminal = new Charger();

					try {
						terminal.initCommunications();
					} catch (IncorrectSequenceNumberException | GeneralSecurityException
							| IncorrectResponseCodeException | CardBlockedException | IncorrectCertificateException e) {
						e.printStackTrace();
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
				break;

			case 3:
				try {
					TerminalWithPin terminal = new Pumper();

					try {
						terminal.initCommunications();
					} catch (IncorrectSequenceNumberException | GeneralSecurityException
							| IncorrectResponseCodeException | CardBlockedException | IncorrectCertificateException e) {
						e.printStackTrace();
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
				break;
			default:
				break loop;
			}
		}
		scanner.close();
	}
}
