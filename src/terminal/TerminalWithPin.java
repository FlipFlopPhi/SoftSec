package terminal;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Calendar;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import terminal.exception.CardBlockedException;
import terminal.exception.CertificateGenerationException;
import terminal.exception.IncorrectCertificateException;
import terminal.exception.IncorrectResponseCodeException;
import terminal.exception.IncorrectSequenceNumberException;
import terminal.util.ByteBuilder;
import terminal.util.BytesHelper;
import terminal.util.IncorrectAckException;
import terminal.util.MismatchedHashException;
import terminal.util.Triple;
import terminal.util.Util;

public abstract class TerminalWithPin implements Pinnable {

	private final PublicKey publicM;

	private final PrivateKey privateT;
	private final byte[] certificateT;
	public final int terminalNumber;

	private byte[] supportedCardVersions = new byte[] { 1 };

	public final TerminalType type;

	public TerminalWithPin(TerminalType type) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, CertificateGenerationException {
		this.type = type;

		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(new RSAKeyGenParameterSpec(Util.MODULUS_LENGTH * 8, BigInteger.valueOf(65537)));
		// TODO: THIS IS NOW HARDCODED DO NOT RELEASE THIS CODE
		KeyPair kp = generator.generateKeyPair();
		privateT = kp.getPrivate();
		try {
			certificateT = BackEnd.getInstance().requestCertificate((RSAPublicKey) kp.getPublic());
		} catch (GeneralSecurityException e) {
			throw new CertificateGenerationException();
		}

		publicM = BackEnd.getInstance().getPublicMasterKey();
		terminalNumber = 0;// TODO get the terminalNumber from the backend or somewhere else
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
		System.out.println(
				"PIN entered incorrectly too many times" + ", we suspect you are a criminal and will be terminated.");
	}

	public void initCommunications() throws CardException, IncorrectSequenceNumberException, GeneralSecurityException,
			IncorrectResponseCodeException, CardBlockedException, IncorrectCertificateException, IncorrectAckException, MismatchedHashException {
		CardTerminal reader = TerminalFactory.getDefault().terminals().list().get(0);
		Card card = reader.connect("*");
		Triple<SecretKey, PublicKey, Integer> keys = Util.handSjaak(card, type, supportedCardVersions, certificateT,
				publicM, privateT);
		SecretKey aesKey = keys.first;
		PublicKey publicC = keys.second;
		restOfTheCard(card, aesKey, publicC, keys.third, Util.verifyPin(card, aesKey, this));
	}

	protected abstract void restOfTheCard(Card card, SecretKey aesKey, PublicKey publicC, int cardNumber, byte[] bs)
			throws NoSuchAlgorithmException, CardException, GeneralSecurityException, IncorrectResponseCodeException,
			IncorrectCertificateException;

}
