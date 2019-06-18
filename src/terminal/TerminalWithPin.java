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
import java.util.Random;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import mvcIO.CMDController;
import mvcIO.CMDView;
import mvcIO.Controller;
import mvcIO.View;
import terminal.exception.CardBlockedException;
import terminal.exception.CertificateGenerationException;
import terminal.exception.IncorrectAckException;
import terminal.exception.IncorrectCertificateException;
import terminal.exception.IncorrectResponseCodeException;
import terminal.exception.IncorrectSequenceNumberException;
import terminal.exception.InvalidPinException;
import terminal.exception.MismatchedHashException;
import terminal.util.ByteBuilder;
import terminal.util.BytesHelper;
import terminal.util.Triple;
import terminal.util.Util;

public abstract class TerminalWithPin implements Pinnable {

	private final PublicKey publicM;
	
	protected final View output;
	protected final Controller input;

	protected final PrivateKey privateT;
	private final byte[] certificateT;
	public final int terminalNumber;

	private byte[] supportedCardVersions = new byte[] { 1 };

	public final TerminalType type;

	public TerminalWithPin(TerminalType type) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, CertificateGenerationException {
		this.type = type;
		//terminalNumber = new Random().nextInt();
		terminalNumber = 1;

		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(new RSAKeyGenParameterSpec(Util.MODULUS_LENGTH * 8, BigInteger.valueOf(65537)));
		KeyPair kp = generator.generateKeyPair();
		privateT = kp.getPrivate();
		try {
			certificateT = BackEnd.getInstance().requestCertificate((RSAPublicKey) kp.getPublic(), terminalNumber);
		} catch (GeneralSecurityException e) {
			throw new CertificateGenerationException();
		}

		publicM = BackEnd.getInstance().getPublicMasterKey();
		
		
		output = new CMDView();
		input = new CMDController();
	}

	@Override
	public byte[] enterPin() throws InvalidPinException {
		output.println("Please enter your pin");
		int pin = input.nextInt();
		if (pin < 0 | pin >= 10000) {
			output.println("Not a valid pin");
			throw new InvalidPinException(pin);
		}
		return ByteBuffer.allocate(Integer.BYTES).putInt(pin).array();
	}

	@Override
	public void showSucces() {
		output.println("PIN succesful");
	}

	@Override
	public void showFailed() {
		output.println("PIN entered incorrect, try again");
	}

	@Override
	public void showBlocked() {
		output.println(
				"PIN entered incorrectly too many times" + ", we suspect you are a criminal and will be terminated.");
	}

	public void initCommunications() throws CardException, IncorrectSequenceNumberException, GeneralSecurityException,
			IncorrectResponseCodeException, CardBlockedException, IncorrectCertificateException, IncorrectAckException, MismatchedHashException {
		CardTerminal reader = TerminalFactory.getDefault().terminals().list().get(0);
		Card card = reader.connect("*");
		Util.sendSelect(card);
		
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
