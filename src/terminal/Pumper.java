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

	public Pumper()
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, CertificateGenerationException {
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
			/** the actual transactionInfo, unencrypted */
			ByteBuilder transactionInfo = new ByteBuilder(Integer.BYTES + 4 + Integer.BYTES + Integer.BYTES);
			transactionInfo.add(DECREMENT_AMOUNT).add(date).add(terminalNumber).add(cardNumber);
			byte[] msg = Arrays.copyOf(Util.encrypt(privateT, transactionInfo.array),
					Util.MODULUS_LENGTH + Util.HASH_LENGTH);
			byte[] transactionInfoHashed = Util.hash(transactionInfo.array);
			for (int i = 0; i < transactionInfoHashed.length; i++)
				msg[transactionInfo.length + i] = transactionInfoHashed[i];
			byte[] certificate = Util.decryptAES(aesKey,
					Util.communicate(card, Step.Pump1, Util.encryptAES(aesKey, msg), 0));
			/** The returned message decrypted once*/
			ByteBuilder decryptedCert = new ByteBuilder(128);
			decryptedCert.add(Util.decrypt(publicC, Arrays.copyOfRange(certificate, 0, 128)))
					.add(Util.decrypt(publicC, Arrays.copyOfRange(certificate, 128, 256)));

			if (!Arrays.equals(Util.encrypt(privateT, transactionInfo.array), decryptedCert.array))
				throw new IncorrectCertificateException(Util.encrypt(privateT, transactionInfo.array),
						decryptedCert.array);
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
