/**
 * 
 */
package terminal;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Calendar;
import java.util.TimeZone;

import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import terminal.util.ByteBuilder;
import terminal.util.BytesHelper;
import terminal.util.Util;

/**
 * @author pspaendonck
 *
 */
public class Personalizer {

	
	public static void personalize() throws CardException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		CardTerminal reader = TerminalFactory.getDefault().terminals().list().get(0);
		Card card = reader.connect("*");
		int pin = 1234;
		int cardNumber = 0;
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(new RSAKeyGenParameterSpec(Util.MODULUS_LENGTH*8, BigInteger.valueOf(65535)));
		KeyPair kp = generator.generateKeyPair();
		PrivateKey privateC = kp.getPrivate();
		ByteBuilder keyPinNr = new ByteBuilder(Util.KEY_LENGTH + Integer.BYTES + Integer.BYTES);
		keyPinNr.add(privateC.getEncoded()).add(pin).add(cardNumber);
		Util.communicate(card, Step.Personalize, keyPinNr.array, 1); 
		
		Util.communicate(card, Step.Personalize2
				, BackEnd.getInstance().getPublicMasterKey().getEncoded()
				, 1);
		
		PublicKey publicC = kp.getPublic();
		Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		calendar.add(Calendar.YEAR, 5);
		ByteBuilder certificateInfo = new ByteBuilder(Util.KEY_LENGTH + 2);
		certificateInfo.add(publicC.getEncoded()).add(BytesHelper.fromDate(calendar));
		byte[] certificateC = BackEnd.getInstance().requestMasterEncryption(certificateInfo.array);
		
		Util.communicate(card, Step.Personalize3, certificateC, 1);
		
		BackEnd.getInstance().storeCardInfo(cardNumber, publicC);//TODO integrate personal user information
	}
}
