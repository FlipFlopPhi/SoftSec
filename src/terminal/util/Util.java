/**
 * 
 */
package terminal.util;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.smartcardio.*;

import terminal.InvalidPinException;
import terminal.Pinnable;
import terminal.Step;
import terminal.TerminalType;
import terminal.exception.CardBlockedException;
import terminal.exception.IncorrectResponseCodeException;
import terminal.exception.IncorrectSequenceNumberException;

/**
 * @author pspaendonck
 *
 */
public final class Util {

	public final static int MODULUS_LENGTH = 125;
	public final static int EXPONENT_LENGTH = 3;
	public final static int KEY_LENGTH = MODULUS_LENGTH + EXPONENT_LENGTH;
	public final static int AES_KEYSIZE = 128; // AES keysize in number of bits
	public final static int DATE_BYTESIZE = 2;
	public final static int CERTIFICATE_BYTESIZE = 256;
	public final static int CARDNUMBER_BYTESIZE = 4;
	public final static int HASH_LENGTH = 16;
	public final static byte PIN_SUCCESFUL = 0;
	public final static byte PIN_FAILED = 1;
	public final static byte PIN_BLOCKED = 2;
	public final static byte ACK = 1;
	public final static int AMOUNTONCARD_BYTESIZE = Short.BYTES;

	/**
	 * 
	 * @param card         the card in the terminal
	 * @param type         the type of the terminal
	 * @param versions     a byte array in which each element is a version number
	 * @param certificateT (See design document)
	 * @param publicM      the public masterkey
	 * @param privateT     the private key of the terminal
	 * @return A symmetric AES secretKey to be used for further communications.
	 * @throws IncorrectSequenceNumberException These are thrown when the
	 *                                          sequenceNumber of a reply is
	 *                                          different then the one expected,
	 *                                          this will probably mean somebody is
	 *                                          trying to alter the communication.
	 * @throws CardException                    These are thrown when an error
	 *                                          happens during communications with
	 *                                          the card.
	 * @throws GeneralSecurityException         These are thrown when an error
	 *                                          happens during encryption or
	 *                                          decryption.
	 * @throws IncorrectAckException
	 * @throws MismatchedHashException 
	 */
	public final static Triple<SecretKey, PublicKey, Integer> handSjaak(Card card, TerminalType type, byte[] versions,
			byte[] certificateT, PublicKey publicM, PrivateKey privateT)
			throws IncorrectSequenceNumberException, GeneralSecurityException, CardException, IncorrectAckException, MismatchedHashException {
		// Generate SequenceNumber first
		final short R = (short) Math.floorMod((int) Math.random(), 2 ^ 15);

		// Generate the initial handshake message (The Hello)
		ByteBuilder initMsg = new ByteBuilder(1 + 1 + versions.length + 2 + 128);
		initMsg.add(type.getByte()).add(versions.length).add(versions).add(R).add(certificateT, 0, 128);

		// Start Communication
		try {
			if (communicate(card, Step.Handshake1, initMsg.array, 1)[0] != ACK)
				throw new IncorrectAckException();
			byte[] reply = communicate(card, Step.Handshake2,
					Arrays.copyOfRange(certificateT, 128, CERTIFICATE_BYTESIZE), CARDNUMBER_BYTESIZE + 1 + 128 + 64);
			int cardNumber = (reply[0] * 2 ^ 24) + reply[1] * 2 ^ 16 + reply[2] * 2 ^ 8 + reply[3];
			byte version = reply[CARDNUMBER_BYTESIZE];
			// TODO: Make support for version handling of card and terminal on the
			// terminalside.
			byte[] reply2 = communicate(card, Step.Handshake3, new byte[] { ACK }, 192);
			byte[] certificateC1 = Arrays.copyOfRange(reply, 0, 128);
			for (int i = 64; i < 128; i++)
				certificateC1[i] = reply2[i - 64];
			certificateC1 = decrypt(publicM, certificateC1);
			// We want to retrieve the publicC first
			PublicKey publicC = KeyFactory.getInstance("RSA").generatePublic(
					new RSAPublicKeySpec(new BigInteger(Arrays.copyOfRange(certificateC1, 0, MODULUS_LENGTH)),
							new BigInteger(Arrays.copyOfRange(certificateC1, MODULUS_LENGTH, KEY_LENGTH))));
			byte[] sequenceNumberEncrypted = Arrays.copyOfRange(reply, CARDNUMBER_BYTESIZE + 1,
					CARDNUMBER_BYTESIZE + 1 + 128);
			short returnedSeqNr = BytesHelper.toShort(decrypt(publicC, sequenceNumberEncrypted));
			short randomIncrement = (short) Math.floorMod(returnedSeqNr - R, 2 ^ 15);

			byte[] certificateC2 = new byte[128];
			for (int i = 0; i < 128; i++)
				certificateC2[i] = reply2[64 + i];
			byte[] dateNHash = decrypt(publicM, certificateC2);
			// TODO: check the certificate's date.
			byte[] certificateC = Arrays.copyOf(certificateC1, 128 + 2);
			certificateC[128] = dateNHash[0];
			certificateC[129] = dateNHash[1];
			if (Arrays.equals(hash(Arrays.copyOfRange(dateNHash, 2, 18)), hash(certificateC))) {
				throw new MismatchedHashException();
			}
			
			// Send Message 3transmit
			KeyGenerator generator = KeyGenerator.getInstance("AES");
			generator.init(AES_KEYSIZE); // advanced Encryption Standard as specified by NIST in FIPS 197.
			SecretKey aesKey = generator.generateKey();
			byte[] keyMsg = Arrays.copyOf(aesKey.getEncoded(), AES_KEYSIZE / 8 + 2);
			byte[] incrementedR = BytesHelper.fromShort((short) Math.floorMod(R + 2 * randomIncrement, 2 ^ 15));
			keyMsg[AES_KEYSIZE / 8] = incrementedR[0];
			keyMsg[AES_KEYSIZE / 8 + 1] = incrementedR[1];
			// Send + Response
			reply = communicate(card, Step.Handshake4, encrypt(publicC, encrypt(privateT, keyMsg)), 16);
			sequenceNumberEncrypted = decrypt(aesKey, "AES", reply);
			if (returnedSeqNr != (byte) Math.floorMod(R + 3 * randomIncrement, 2 ^ 15))
				throw new IncorrectSequenceNumberException();
			return new Triple<SecretKey, PublicKey, Integer>(aesKey, publicC, Integer.valueOf(cardNumber));
		} catch (CardException e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * AES_KEYSIZE
	 * 
	 * @param card     the card in the terminal
	 * @param key      the symmetric key used for communication
	 * @param terminal the Pinnable interface used to call terminal methods.
	 * @return a byte array containing the amount of credit stored on the card.e of
	 *         the Modulus (par
	 * @throws CardException                  These are thrown when
	 *                                        ancardReader.waitForCardPresent(0);
	 *                                        Card card = cardReader.connect("*");
	 *                                        //Establish connection using any
	 *                                        protocol available
	 *                                        Util.handSjaak(card,
	 *                                        TerminalType.CHARGER, versions,
	 *                                        certificateT, publicM, privateT) error
	 *                                        happens during communications with the
	 *                                        card.
	 * @throws GeneralSecurityException       These are thrown when an error happens
	 *                                        during encryption or decryption.
	 * @throws IncorrectResponseCodeException These are thrown when the response
	 *                                        code send in step 4 is not recognized
	 *                                        this usually means the signal is being
	 *                                        jammed.
	 * @throws CardBlockedException           This one is thrown if the card get
	 *                                        blocked in the pinning process. This
	 *                                        is used to communicate with the
	 *                                        terminal executing this function.
	 */
	public final static byte[] verifyPin(Card card, SecretKey key, Pinnable terminal)
			throws CardException, GeneralSecurityException, IncorrectResponseCodeException, CardBlockedException {
		while (true) {
			byte[] pin;
			try {
				pin = terminal.enterPin();
			} catch (InvalidPinException e) {
				e.printStackTrace();
				continue;
			}
			byte[] msg = Arrays.copyOf(pin, pin.length + HASH_LENGTH);// Copy the pin, leaving room for the hash of the
																		// pin.
			byte[] hash = hash(pin);
			for (int i = 0; i < HASH_LENGTH; i++)
				msg[pin.length + i] = hash[i];
			byte[] reply = decrypt(key, "AES",
					communicate(card, Step.Pin, encrypt(key, "AES", msg), 16));
			if (reply[0] == PIN_SUCCESFUL) {
				byte[] amountOnCard = Arrays.copyOfRange(reply, 1, reply.length);
				terminal.showSucces();
				return amountOnCard;
			} else if (reply[0] == PIN_FAILED) {
				terminal.showFailed();
				continue;
			} else if (reply[0] == PIN_BLOCKED) {
				terminal.showBlocked();
				card.disconnect(false);
				throw new CardBlockedException();
			} else {
				throw new IncorrectResponseCodeException(reply[0]);
			}

		}
	}

	public static void printAPDU (CommandAPDU apdu) {
		String response = "C: L:" + apdu.getBytes().length + " ";
		for (byte b : apdu.getBytes()) {
			response += String.format("%02x,",b);
		}
		System.out.println(response);
	}

	public static void printAPDU (ResponseAPDU apdu) {
		String response = "R: L:" + apdu.getBytes().length + " ";
		for (byte b : apdu.getBytes()) {
			response += String.format("%02x,",b);
		}
		System.out.println(response);
	}

	public static byte[] communicate(Card card, Step step, byte[] message, int responseLength) throws CardException {
		CardChannel channel = card.getBasicChannel();
		byte[] APP_ID = {(byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78, (byte) 0x90, (byte) 0xab, };
		ResponseAPDU response = channel.transmit(new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, APP_ID));

		/*
		byte[] test= {0x04, 0x03, 0x02, 0x01};
		printAPDU(new CommandAPDU(0xD0, 0, step.P1, 25, test, 4));
		response = channel.transmit(new CommandAPDU(0xD0, 0, step.P1, 25, test, 4));
		printAPDU(response);
		*/

		printAPDU(new CommandAPDU(0xD0, (byte) 0, step.P1, step.P2, message, responseLength));
		response = channel
				.transmit(new CommandAPDU(0xD0, (byte) 0, step.P1, step.P2, message, responseLength));
		printAPDU(response);
		int sw1 = response.getSW1();
		if (sw1 == 0x61 | sw1 == 0x90)
			return response.getData();
		throw new CardException("Response Error returned" + response.getSW1() + "," + response.getSW2());
	}

	/**
	 * @author https://gist.github.com/dmydlarz/32c58f537bb7e0ab9ebf
	 * @param privateKey
	 * @param message
	 * @return
	 * @throws Exception
	 */
	public static byte[] encrypt(Key privateKey, byte[] message) throws GeneralSecurityException {
		return encrypt(privateKey, "RSA", message);
	}

	public static byte[] encrypt(Key key, String scheme, byte[] message) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(scheme);
		cipher.init(Cipher.ENCRYPT_MODE, key);

		return cipher.doFinal(message);
	}

	/**
	 * * @author https://gist.github.com/dmydlarz/32c58f537bb7e0ab9ebf
	 * 
	 * @param publicKey
	 * @param encrypted
	 * @return
	 */
	public static byte[] decrypt(Key publicKey, byte[] encrypted) throws GeneralSecurityException {
		return decrypt(publicKey, "RSA", encrypted);// Uses RSA as defined in PKCS #1
	}

	public static byte[] decrypt(Key key, String scheme, byte[] encrypted) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(scheme);
		cipher.init(Cipher.DECRYPT_MODE, key);

		return cipher.doFinal(encrypted);
	}

	public static byte[] hash(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		return md.digest(data);
	}
}
