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
import java.util.Random;
import java.util.Scanner;
import java.util.TimeZone;

import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
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

			Util.sendSelect(card);
			
			Scanner in = new Scanner(System.in);
			System.out.println("Please enter your 4 digit pincode:");
			int pin = in.nextInt();
			while(pin < 1000 | pin >9999) {
				System.out.println("Pin entered incorrectly, please try again");
			}
			System.out.println("Please enter your name:");
			String name = in.nextLine();
			
			System.out.println("Please enter your BSN:");
			BigInteger bsn = in.nextBigInteger();
			in.close();
			
			
			
			
			int cardNumber = new Random().nextInt();
			BackEnd.getInstance().registerCard(cardNumber, new Account(name, bsn));
			
			KeyPairGenerator generator;
			try {
				generator = KeyPairGenerator.getInstance("RSA");
			} catch (NoSuchAlgorithmException e1) {
				throw new FailedPersonalizationException("No version of RSA is available on this terminal.");
			}
			try {
				generator.initialize(new RSAKeyGenParameterSpec(Util.MODULUS_LENGTH*8, BigInteger.valueOf(65537)));
			} catch (InvalidAlgorithmParameterException e1) {
				throw new FailedPersonalizationException("An error in the keyspecs has occured, please contact the developers.\n"+e1.getMessage());
			}
			KeyPair kp = generator.generateKeyPair();
			RSAPrivateKey privateC = (RSAPrivateKey) kp.getPrivate();
			Util.communicate(card, Step.Personalize, Arrays.copyOfRange(privateC.getModulus().toByteArray(),1,129), 1);
			
			Util.communicate(card, Step.Personalize2, privateC.getPrivateExponent().toByteArray(), 1);
			
			byte[] certificateC; try {
				certificateC = BackEnd.getInstance().requestCertificate((RSAPublicKey)kp.getPublic(), cardNumber);

			} catch (GeneralSecurityException e) {
				e.printStackTrace();
				throw new FailedPersonalizationException("Encrypting certificates using backEnd failed.");
			}
			ByteBuilder persT3 = new ByteBuilder(Util.MODULUS_LENGTH + 3 + 64 + Integer.BYTES + Integer.BYTES);
			persT3.addPublicRSAKey(BackEnd.getInstance().getPublicMasterKey())
				.add(Arrays.copyOf(certificateC, 64)).add(pin).add(cardNumber);
			Util.communicate(card, Step.Personalize3, persT3.array, 130);
			
			Util.communicate(card, Step.Personalize4, Arrays.copyOfRange(certificateC, 64, 256), 1);
			
			BackEnd.getInstance().storeCardInfo(cardNumber, kp.getPublic());//TODO integrate personal user information
		} catch (CardException e1) {
			e1.printStackTrace();
			throw new FailedPersonalizationException("Could not connect with a card for personalization.");
		}
		
		
	}
}
