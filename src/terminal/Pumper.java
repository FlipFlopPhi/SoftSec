/**
 * 
 */
package terminal;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import javax.crypto.SecretKey;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;

import terminal.exception.IncorrectResponseCodeException;
import terminal.util.BytesHelper;

/**
 * @author pspaendonck
 *
 */
public class Pumper extends TerminalWithPin {
	

	public Pumper() {
		super(TerminalType.PUMP);
	}

	@Override
	protected void restOfTheCard(Card card, SecretKey aesKey, byte[] bs) 
			throws NoSuchAlgorithmException, CardException, GeneralSecurityException, IncorrectResponseCodeException {
		byte[] date = BytesHelper.fromPreciseDate();
		byte[] transactionInfo = Arrays.copyOf(date
				, 4 + Util.HASH_LENGTH + Integer.BYTES + Util.HASH_LENGTH);
		byte[] dateHash = Util.hash(date);
		for (int i=0; i<Util.HASH_LENGTH; i++)
			transactionInfo[4+i] = dateHash[i];
		byte[] terminalBytes;
		//TODO: Continue from here on
	}
	
	

}
