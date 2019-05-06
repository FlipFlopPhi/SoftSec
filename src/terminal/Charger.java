/**
 * 
 */
package terminal;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.smartcardio.Card;

import terminal.util.BytesHelper;

/**
 * @author pspaendonck
 *
 */
public class Charger extends TerminalWithPin {

	public final static int MAXIMUM_ALLOWED_CREDIT_STORED = 300_00;
	public Charger() {
		super(TerminalType.CHARGER);
	}

	@Override
	protected void restOfTheCard(Card card, SecretKey aesKey, byte[] bs) throws NoSuchAlgorithmException {
		int amountOnCard = BytesHelper.toInt(bs);
		byte[] amountRequested = getRequestedAmount(amountOnCard);
		byte[] requestMsg = Arrays.copyOf(amountRequested, Integer.BYTES+Util.HASH_LENGTH);
		byte[] hash = Util.hash(amountRequested);
		for(int i=0; i<hash.length; i++)
			requestMsg[Integer.BYTES + i] = hash[i];
		Account.testAccount.decreaseBy(amountRequested);
		try {
			byte[] reply = Util.communicate(card, Step.Charge
					, Util.encrypt(aesKey, "AES", requestMsg), 1);
		} catch(Exception e) {
			Account.testAccount.increaseBy(amountRequested);
		}
	}

	/**
	 * Function that should ask the user for an amount they want to request to be put on the card, this function should make sure this will not lead to a total
	 * above the MAXIMUM_ALLOWED_CREDIT_STORED.
	 * @param amountOnCard the amount on the 
	 * @return
	 */
	private byte[] getRequestedAmount(int amountOnCard) {
		// TODO Auto-generated method stub
		return null;
	}

	
}
