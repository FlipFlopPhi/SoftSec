/**
 * 
 */
package terminal;


import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.smartcardio.*;

import terminal.exception.CardBlockedException;
import terminal.exception.IncorrectResponseCodeException;
import terminal.exception.IncorrectSequenceNumberException;
import terminal.util.BytesHelper;
/**
 * @author pspaendonck
 *
 */
public final class Util {
	
	final static int MODULUS_LENGTH = 64;
	final static int EXPONENT_LENGTH = 64;
	final static int KEY_LENGTH = MODULUS_LENGTH + EXPONENT_LENGTH;
	final static int AES_KEYSIZE = 128; //AES keysize in number of bits
	final static int DATE_BYTESIZE = 2;
	final static int CERTIFICATE_BYTESIZE = KEY_LENGTH+ DATE_BYTESIZE;
	final static int CARDNUMBER_BYTESIZE = 4;
	final static int HASH_LENGTH = 16;
	final static byte PIN_SUCCESFUL = 0;
	final static byte PIN_FAILED = 1;
	final static byte PIN_BLOCKED = 2;
	public final static int AMOUNTONCARD_BYTESIZE = Short.BYTES;

	/**
	 * 
	 * @param card the card in the terminal
	 * @param type the type of the terminal
	 * @param versions a byte array in which each element is a version number
	 * @param certificateT (See design document)
	 * @param publicM the public masterkey
	 * @param privateT the private key of the terminal
	 * @return A symmetric AES secretKey to be used for further communications.
	 * @throws IncorrectSequenceNumberException These are thrown when the sequenceNumber of a reply is different then the one expected,
	 * 	this will probably mean somebody is trying to alter the communication.
	 * @throws CardException These are thrown when an error happens during communications with the card.
	 * @throws GeneralSecurityException These are thrown when an error happens during encryption or decryption.
	 */
	public final static	SecretKey handSjaak(Card card
			, TerminalType type, byte[] versions
			, byte[] certificateT, PublicKey publicM
			, PrivateKey privateT) 
					throws IncorrectSequenceNumberException, GeneralSecurityException, CardException {
		//Generate SequenceNumber first
		final short R = (short) Math.floorMod((int) Math.random(), 2^15);
		//Generate the initial handshake message (The Hello)
		byte[] initMsg = new byte[1 + 1+versions.length + 2 + certificateT.length];
		initMsg[1] = type.getByte();
		int i=2;
		for(byte version : versions) {
			initMsg[i] = version;
			i++;
		}
		byte[] seqNr = ByteBuffer.allocate(Short.BYTES).putShort(R).array();
		initMsg[i++] = seqNr[0];
		initMsg[i++] = seqNr[1];
		for(byte b : certificateT) {
			initMsg[i] = b;
			i++;
		}
		//Start Communication
		try {
			byte[] reply = communicate(card, Step.Handshake1, initMsg, CARDNUMBER_BYTESIZE + 1 + 2 + certificateT.length);
			int cardNumber = (reply[0]*2^24) + reply[1]*2^16 + reply[2]*2^8 + reply[3];
			byte version = reply[CARDNUMBER_BYTESIZE];
			//We want to retrieve the publicC first
			byte[] certificateC = decrypt(publicM, Arrays.copyOfRange(reply, CARDNUMBER_BYTESIZE+2,reply.length));
			PublicKey publicC = KeyFactory.getInstance("RSA").generatePublic( 
					new RSAPublicKeySpec(new BigInteger(Arrays.copyOfRange(certificateC,0,MODULUS_LENGTH))
							,new BigInteger(Arrays.copyOfRange(certificateC, MODULUS_LENGTH, KEY_LENGTH))
							)
					);
			byte[] sequenceNumberEncrypted =  Arrays.copyOfRange(reply, CARDNUMBER_BYTESIZE, CARDNUMBER_BYTESIZE+1);
			short returnedSeqNr = BytesHelper.toShort(decrypt(publicC, sequenceNumberEncrypted));
			short randomIncrement = (short) Math.floorMod(returnedSeqNr - R, 2^15);
			
			// Send Message 3transmit
			KeyGenerator generator = KeyGenerator.getInstance("AES");
			generator.init(AES_KEYSIZE); // advanced Encryption Standard as specified by NIST in FIPS 197.
			SecretKey aesKey = generator.generateKey();
			byte[] keyMsg = Arrays.copyOf(aesKey.getEncoded(), AES_KEYSIZE/8+2);
			byte[] incrementedR = BytesHelper.fromShort((short) Math.floorMod(R+2*randomIncrement, 2^15));
			keyMsg[AES_KEYSIZE/8] = incrementedR[0];
			keyMsg[AES_KEYSIZE/8 +1] = incrementedR[1];
			//Send + Response 
			reply = communicate(card, Step.Handshake2
					, encrypt(publicC,encrypt(privateT,keyMsg))
					, 1);
			sequenceNumberEncrypted = decrypt(aesKey, "AES", reply);
			if (returnedSeqNr !=(byte) Math.floorMod(R+3*randomIncrement, 2^15)) throw new IncorrectSequenceNumberException();
			return aesKey;
		} catch (CardException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw e;
		}
	}
	
	/**
	 * 
	 * @param card the card in the terminal
	 * @param key the symmetric key used for communication
	 * @param terminal the Pinnable interface used to call terminal methods.
	 * @return a byte array containing the amount of credit stored on the card.
	 * @throws CardException These are thrown when ancardReader.waitForCardPresent(0);
		Card card = cardReader.connect("*"); //Establish connection using any protocol available
		Util.handSjaak(card, TerminalType.CHARGER, versions, certificateT, publicM, privateT)
	 error happens during communications with the card.
	 * @throws GeneralSecurityException These are thrown when an error happens during encryption or decryption.
	 * @throws IncorrectResponseCodeException These are thrown when the response code send in step 4 is not recognized
	 * 	this usually means the signal is being jammed.
	 * @throws CardBlockedException This one is thrown if the card get blocked in the pinning process.
	 * 	This is used to communicate with the terminal executing this function.
	 */
	public final static byte[] verifyPin(Card card, SecretKey key, Pinnable terminal) throws CardException, GeneralSecurityException, IncorrectResponseCodeException, CardBlockedException {
		while(true) {
			byte[] pin;
			try {
				pin = terminal.enterPin();
			} catch (InvalidPinException e) {
				e.printStackTrace();
				continue;
			}
			byte[] msg = Arrays.copyOf(pin, pin.length + HASH_LENGTH);//Copy the pin, leaving room for the hash of the pin.
			byte[] hash = hash(pin);
			for(int i=0; i<HASH_LENGTH; i++) 
				msg[pin.length+i] = hash[i];
			byte[] reply = decrypt(key, "AES", communicate(card, Step.Pin
					, encrypt(key, "AES", msg)
					,1 + Short.BYTES)
					);
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
	
	public static byte[] communicate(Card card, Step step, byte[] message, int responseLength) throws CardException {
		CardChannel channel = card.getBasicChannel();
		ResponseAPDU response = channel.transmit(new CommandAPDU(0xD0, 0, step.P1, step.P2, message, message.length, responseLength));
		int sw1 = response.getSW1();
		if (sw1 == 0x61 | sw1 == 90)
			return response.getData();
		throw new CardException("Response Error returned" + response.getSW());
	}
	
	/**
	 * @author https://gist.github.com/dmydlarz/32c58f537bb7e0ab9ebf
	 * @param privateKey
	 * @param message
	 * @return
	 * @throws Exception
	 */
	public static byte[] encrypt(Key privateKey, byte[] message) throws GeneralSecurityException {
        return encrypt(privateKey,"RSA",message);
    }
	
	public static byte[] encrypt(Key key, String scheme, byte[] message) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(scheme);  
        cipher.init(Cipher.ENCRYPT_MODE, key);  

        return cipher.doFinal(message);  
	}
    
	/**
	 * @author https://gist.github.com/dmydlarz/32c58f537bb7e0ab9ebf
	 * @param publicKey
	 * @param encrypted
	 * @return 
	 */
    public static byte[] decrypt(Key publicKey, byte [] encrypted) throws GeneralSecurityException{
    	return decrypt(publicKey, "RSA", encrypted);//Uses RSA as defined in PKCS #1
    }
    
    public static byte[] decrypt(Key key, String scheme, byte[] encrypted) throws GeneralSecurityException{
    	Cipher cipher = Cipher.getInstance(scheme);  
        cipher.init(Cipher.DECRYPT_MODE, key);
        
        return cipher.doFinal(encrypted);
    }
    
    public static byte[] hash(byte[] data) throws NoSuchAlgorithmException {
    	MessageDigest md = MessageDigest.getInstance("MD5");
    	return md.digest(data);
    }
}
