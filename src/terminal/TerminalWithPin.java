package terminal;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import terminal.exception.CardBlockedException;
import terminal.exception.IncorrectResponseCodeException;
import terminal.exception.IncorrectSequenceNumberException;
import terminal.util.Triple;

public class TerminalWithPin implements Pinnable {

	private byte[] supportedCardVersions = new byte[] {1};
	
	public final TerminalType type;
	
	public TerminalWithPin(TerminalType type) {
		this.type = type;
	}
	
	@Override
	public byte[] enterPin() throws InvalidPinException {
		System.out.println("Please enter your pin");
		Scanner scanner = new Scanner(System.in);
		int pin = scanner.nextInt();
		if (pin < 0 | pin >= 10000) {
			System.out.println("Not a valid pin");
			scanner.close();
			throw new InvalidPinException(pin);
		}
		scanner.close();
		return ByteBuffer.allocate(Integer.BYTES).putInt(pin).array();
	}

	@Override
	public void showSucces() {
		System.out.println("PIN succesful");
	}

	@Override
	public void showFailed() {
		System.out.println("PIN entered incorrect, try again");
	}

	@Override
	public void showBlocked() {
		System.out.println("PIN entered incorrectly too many times"
				+ ", we suspect you are a criminal and will be terminated.");
	}

	public Triple<Card, SecretKey,byte[]> initCommunications(byte[] certificateT, PublicKey publicM, PrivateKey privateT) throws CardException, IncorrectSequenceNumberException, GeneralSecurityException, IncorrectResponseCodeException, CardBlockedException {
		CardTerminal reader = TerminalFactory.getDefault().terminals().list().get(0);
		Card card = reader.connect("*");
		SecretKey aesKey = Util.handSjaak(card, type, supportedCardVersions
				, certificateT, publicM, privateT);
		return new Triple<Card, SecretKey, byte[]>(card
				, aesKey
				, Util.verifyPin(card, aesKey, this)
				);
	}

}
