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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Scanner;
import java.util.TimeZone;

import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import terminal.exception.FailedPersonalizationException;
import terminal.util.ByteBuilder;
import terminal.util.BytesHelper;
import terminal.util.Util;

/**
 * @author pspaendonck
 *
 */
public class Personalizer {

	
	public static void personalize() throws FailedPersonalizationException {
		CardTerminal reader;
		try {
			reader = TerminalFactory.getDefault().terminals().list().get(0);
			Card card = reader.connect("*");
			int pin = 1234;
			int cardNumber = 0;
			System.out.println("Is this a new Account? (Y/N)");
			Scanner scanner = new Scanner(System.in);
			String input;
			if ((input = scanner.next()).equals("Y")) {
				BackEnd.getInstance().registerCard(cardNumber, new Account());
			} else {
				scanner.close();
				throw new FailedPersonalizationException("This mode is not supported yet.");
				//TODO do something with this;
			}
			scanner.close();
			KeyPairGenerator generator;
			try {
				generator = KeyPairGenerator.getInstance("RSA");
			} catch (NoSuchAlgorithmException e1) {
				throw new FailedPersonalizationException("No version of RSA is available on this terminal.");
			}
			try {
				generator.initialize(new RSAKeyGenParameterSpec(Util.MODULUS_LENGTH*8, BigInteger.valueOf(65535)));
			} catch (InvalidAlgorithmParameterException e1) {
				throw new FailedPersonalizationException("An error in the keyspecs has occured, please contact the developers.\n"+e1.getMessage());
			}
			KeyPair kp = generator.generateKeyPair();
			byte[] privateC = BytesHelper.fromPrivateKey((RSAPrivateKey) kp.getPrivate());
			Util.communicate(card, Step.Personalize, privateC, 1); 
			
			byte[] certificateC; try {
				certificateC = BackEnd.getInstance().requestCertificate((RSAPublicKey)kp.getPublic());
			} catch (GeneralSecurityException e) {
				throw new FailedPersonalizationException("Encrypting certificates using backEnd failed.");
			}
			ByteBuilder persT2 = new ByteBuilder(Util.MODULUS_LENGTH + 3 + 64 + Integer.BYTES + Integer.BYTES);
			persT2.addPublicRSAKey(BackEnd.getInstance().getPublicMasterKey())
				.add(Arrays.copyOf(certificateC, 64)).add(pin).add(cardNumber);
			Util.communicate(card, Step.Personalize2, persT2.array, 1);
			
			Util.communicate(card, Step.Personalize3, Arrays.copyOfRange(certificateC, 64, 256), 1);
			
			BackEnd.getInstance().storeCardInfo(cardNumber, kp.getPublic());//TODO integrate personal user information
		} catch (CardException e1) {
			throw new FailedPersonalizationException("Could not connect with a card for personalization.");
		}
		
		
	}
}
