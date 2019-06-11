/**
 * 
 */
package terminal;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;

import terminal.exception.CertificateGenerationException;
import terminal.exception.IncorrectCertificateException;
import terminal.exception.IncorrectResponseCodeException;
import terminal.util.ByteBuilder;
import terminal.util.BytesHelper;
import terminal.util.Util;

/**
 * @author pspaendonck
 *
 */
public class Pumper extends TerminalWithPin {

	public final static int DECREMENT_AMOUNT = 3;

	public Pumper() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, CertificateGenerationException {
		super(TerminalType.PUMP);
	}

	@Override
	protected void restOfTheCard(Card card, SecretKey aesKey, PublicKey publicC, int cardNumber, byte[] bs)
			throws NoSuchAlgorithmException, CardException, GeneralSecurityException, IncorrectResponseCodeException,
			IncorrectCertificateException {
		int amountOnCard = BytesHelper.toInt(bs);
		while (!isTankFull() & amountOnCard >= DECREMENT_AMOUNT) {
			amountOnCard -= DECREMENT_AMOUNT;
			byte[] date = BytesHelper.fromPreciseDate();
			ByteBuilder transactionInfo = new ByteBuilder(Integer.BYTES + 4 + Integer.BYTES + Integer.BYTES);
			transactionInfo.add(DECREMENT_AMOUNT).add(date).add(terminalNumber).add(cardNumber);
			byte[] msg = Arrays.copyOf(transactionInfo.array, transactionInfo.length + Util.HASH_LENGTH);
			byte[] transactionInfoHashed = Util.hash(transactionInfo.array);
			for (int i=0;  i < transactionInfoHashed.length; i++)
				msg[transactionInfo.length + i] = transactionInfoHashed[i];
			byte[] certificate = Util.communicate(card, Step.Pump1, Util.encrypt(aesKey, "AES", msg)
					,128);
			byte[] decryptedCert = Util.decrypt(publicC, certificate);
			if (!Arrays.equals(transactionInfo.array, decryptedCert))
				throw new IncorrectCertificateException(msg, decryptedCert);
			store(certificate);
			dispenseFuel(DECREMENT_AMOUNT);
		}
	}

	/**
	 * This method dispenses the requested amount of fuel.
	 * 
	 * @param decrementAmount
	 */
	private void dispenseFuel(int decrementAmount) {
		// TODO Auto-generated method stub

	}

	/**
	 * Checks whether the cars tank is full
	 * 
	 * @return
	 */
	private boolean isTankFull() {
		// TODO Auto-generated method stub
		return false;
	}

	/**
	 * This method takes care of storing receipts, so that they can be used as proof
	 * of transactions.
	 * 
	 * @param certificate
	 */
	private void store(byte[] receipt) {
		// TODO Auto-generated method stub

	}

}
