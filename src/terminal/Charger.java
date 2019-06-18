/**
 * 
 */
package terminal;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;

import terminal.exception.CertificateGenerationException;
import terminal.exception.IncorrectResponseCodeException;
import terminal.util.ByteBuilder;
import terminal.util.BytesHelper;
import terminal.util.Util;

/**
 * @author pspaendonck
 *
 */
public class Charger extends TerminalWithPin {

	public final static int MAXIMUM_ALLOWED_CREDIT_STORED = 300_00;//Maximum allowed credit to be stored on card in cents
	public final static byte TRANSFER_SUCCESSFUL = 1;
	
	public Charger() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, CertificateGenerationException {
		super(TerminalType.CHARGER);
	}

	@Override
	protected void restOfTheCard(Card card, SecretKey aesKey, PublicKey publicC, int cardNumber, byte[] bs) throws CardException, GeneralSecurityException, IncorrectResponseCodeException {
		int amountOnCard = BytesHelper.toInt(bs);
		Account cardholder = BackEnd.getInstance().getAccount(cardNumber);
		byte[] amountRequested = BytesHelper.fromInt(getRequestedAmount(amountOnCard, cardholder));
		ByteBuilder msg= new ByteBuilder(Util.AES_KEYSIZE/8*2);
		msg.add(Util.encryptAES(aesKey, amountRequested)).add(Util.encryptAES(aesKey, Util.hash(amountRequested)));
		Account.testAccount.decreaseBy(BytesHelper.toInt(amountRequested));
		byte[] reply = Util.communicate(card, Step.Charge, msg.array, 16);
		if (Util.decryptAES(aesKey, reply)[0] != TRANSFER_SUCCESSFUL)
			throw new IncorrectResponseCodeException(TRANSFER_SUCCESSFUL);
	}

	/**
	 * Function that should ask the user for an amount they want to request to be put on the card, this function should make sure this will not lead to a total
	 * above the MAXIMUM_ALLOWED_CREDIT_STORED.
	 * @param amountOnCard the amount on the 
	 * @return
	 */
	private int getRequestedAmount(int amountOnCard, Account account) {
		int max = Math.min(MAXIMUM_ALLOWED_CREDIT_STORED-amountOnCard,account.getCreditStored());
		output.println("Please input the amount of credit [0,"+max+"] you want to move to your card.\n"
				+"Amount stored on account = "+account.getCreditStored()+" Creds\n"
				+"Amount stored on card = "+amountOnCard+" Creds");
		int userInput = input.nextInt();
		while( userInput <0 || userInput > max) {
			output.println("It seems you have entered an invalid amount. \n Please try again.");
			userInput = input.nextInt();
		}
		return userInput;
	}

	
}
