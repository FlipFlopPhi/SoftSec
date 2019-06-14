package rationingapplet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class RationingApplet extends Applet implements ISO7816 {
    // Data definitions
    //private byte someData[];
    private byte notepad[];
    private short oldState[];
    private short sequenceNumber[];
    private byte terminalType[];
    private RSAPrivateKey cardPrivateKey;
    private RSAPublicKey terminalPublicKey;
    private RSAPublicKey masterKey;
    private AESKey symmetricKey;
    private byte cardCertificate[];
    private Cipher rSACipher;
    private Cipher aESCipher;
    private RandomData rngesus;
    private MessageDigest hasher;
    private byte cardNumber[];
    private OwnerPIN pin;
    private byte creditOnCard[];
    private static short HASH_BYTESIZE = 16;
    private static short RSA_KEY_BYTESIZE = 131;
    private static short RSA_KEY_MODULUSSIZE = 128;
    private static short RSA_KEY_EXPONENTSIZE = 3;
    private static short AES_KEY_BYTESIZE = 16; // 128/8
    private static short DATE_BYTESIZE = 2;
    private static short TRANSACTIONINFO_BYTESIZE = 16;
    private static short CERTIFICATE_BYTESIZE = 256;
    private static short CERTIFICATE_DECRYPTED_SIZE = 149;
    private static short HANDSHAKE_ONE_INPUT_LENGTH_MIN = 133;
    private static short NOTEPAD_SIZE = 520;
    private static byte VERSION_NUMBER = 1;

    public RationingApplet() {
    	//Hey Toon ik hoop dat ik hier gewoon dingen mag invoeren :3
    	creditOnCard = new byte[4];
    	for(short i=0; i<3; i++) {
    		creditOnCard[i] = (byte) 0;
    	}
    	creditOnCard[(short) 3] = (byte) 100;
    	
    	
        //Do data allocations here.
        //someData = new byte[10]; // persistent data, stays on the card between resets
        //someData = JCSystem.makeTransientByteArray((short) 10, JCSystem.CLEAR_ON_RESET); // transient data, is cleared when the card is removed from the terminal.

        //300 bytes of memory that should be used as temporary storage of byte arrays instead of defining different arrays for every single thing.
        notepad = JCSystem.makeTransientByteArray((short) NOTEPAD_SIZE, JCSystem.CLEAR_ON_RESET);

        //TODO get all the upcoming variables from personalizing
        masterKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
//        masterKey.setExponent(buffer, offset, length);
//        masterKey.setModulus(buffer, offset, length);
        cardPrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);
//        cardPrivateKey.setExponent(buffer, offset, length);
//        cardPrivateKey.setModulus(buffer, offset, length);
        cardCertificate = new byte[CERTIFICATE_BYTESIZE];
        cardNumber = new byte[4];

        // Max tries = 3, max size = 4
        pin = new OwnerPIN((byte) 4, (byte) 4);

        rSACipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        //AES algorithm:
        aESCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        
        rngesus = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        // Hashing
        hasher = MessageDigest.getInstance(MessageDigest.ALG_MD5, false);

        oldState = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
        sequenceNumber = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET); // The sequence number and how much is added per increment.

        // Handshake step 1
        terminalType = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        terminalPublicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);

		// Handshake step 3
		symmetricKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);

        // Finally, register the applet.
        register();
    }

    /**
     * Called by the JavaCard OS when the applet is selected. Can be overwritted to be used for initializations
     * @return True if the selection of the applet was successful, false otherwise
     */
    public boolean select() {
        oldState[0] = (short) 0;
        sequenceNumber[0] = (short) 0;
        return true;
    }

    /*public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        return null;
    }*/

    /**
     * Called when the applet is installed on the card, note that the data allocation currently performed in the
     * constructor can be done here instead. In that case, do not forget to call the register()-method of the app.
     * See also the JavaCard API documentation for javacard.framework.RationingApplet.install()
     * @param bArray The array containing installation parameter
     * @param bLength The starting offset in bArray
     * @param bOffset The length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RationingApplet();
    }

    /**
     * Called whenever the terminal sends an APDU message to the card, this includes the messages that opens (selects)
     * the applet from the OS.
     * @param apdu The data sent to the card
     */
    public void process(APDU apdu) {
        // Get the byte array from the received APDU, this includes the header.
        byte[] buffer = apdu.getBuffer();
        // Find out how long the incoming data is in bytes (the 5th byte of the APDU buffer)
        byte dataLength = buffer[OFFSET_LC];
        if (selectingApplet()) {
            return;
        }

        short terminalState = Util.makeShort(buffer[OFFSET_P1], buffer[OFFSET_P2]);

        switch(terminalState) {
            case 1:
                if (oldState[0] != (short) 0 && oldState[0] != (short) 11) { //TODO 10 weghalen lol
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                }
                handshakeStepOne(apdu, dataLength);

                break;
            case 2:
                if (oldState[0] != (short) 1) {
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                }
                handshakeStepTwo(apdu, dataLength);

                break;
            case 3:
                if (oldState[0] != (short) 2) {
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                }
                handshakeStepThree(apdu, dataLength);
                break;
            case 4:
                if (oldState[0] != (short) 3) {
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                }
                handshakeStepFour(apdu, dataLength);
                break;
            case 5:
            	if (oldState[0] != (short) 4) {
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                }
                handshakeStepFive(apdu, dataLength);
                break;
            
            case 12:
                if (oldState[0] != (short) 5 && oldState[0] != (short) 12) {
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                }
                pinStep(apdu, dataLength);
                break;
            case 6:
                if (oldState[0] != (short) 12) {
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                }
                chargeStep(apdu, dataLength);
                break;
            case 7:
                if (oldState[0] != (short) 12 && oldState[0] != (short) 7) {
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                }
                pumpStep(apdu, dataLength);

                break;
            case 8:
                if (oldState[0] != (short) 0) { //TODO onbereikbaar maken lol
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                }
                personalizeStepOne(apdu, dataLength);

                break;
            case 9:
                if (oldState[0] != (short) 8) {
                    //ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                	ISOException.throwIt(oldState[0]);
                }
                personalizeStepTwo(apdu, dataLength);

                break;
            case 10:
                if (oldState[0] != (short) 9) {
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                }
                personalizeStepThree(apdu, dataLength);

                break;
            case 11:
            	if (oldState[0] != (short) 10) {
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);            		
            	}
            	personalizeStepFour(apdu, dataLength);
            	
            	break;
            case 25:
                debugStep(apdu, dataLength);
                terminalState = 0;
                break;
            default:

                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                break;
        }
        oldState[0] = terminalState;

        /*// Response (1 byte)
        short returnLength = apdu.setOutgoing();
        if (returnLength != (short) 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);
        //Util.setShort(buffer, (short) 0, (short) (dataLength));//(byte) 1;
        //buffer[0] = 1;
        Util.setShort(buffer, (short) 0, oldState[0]);
        apdu.sendBytes((short) 1, returnLength);
        return;*/
        
        // Extract the returnLength from the apdu buffer (the last byte of the APDU buffer).
        // This is also information is also returned by apdu.setOutgoing(), so I've commented it out here.
        //byte returnLength = buffer[(short)(OFFSET_CDATA + dataLength+1)];

        // Extract the incoming data into a byte array on the card.
        // This is not a necessary step, it might be more memory efficient to not do this, and to extract data from the
        // buffer itself when it is needed. In that case we might have to do some bound checking, I don't know what
        // happens if we request bytes outside of the received input.
        /*byte[] data = new byte[dataLength];
        for (short i = 0; i < dataLength; i++) {
            data[i] = buffer[(short)(OFFSET_CDATA + i+1)];
        }*/

        // process() is also called with the APDU that selected this applet in the first place, ignore that APDU, it
        // has done what it had to do.


        // Set the apdu to outgoing, discards any remaining input data. This also returns the expected output length.
        // I'm not sure what happens if there is no expected response, I expect returnLength to be 0 then (?)
//        short returnLength = apdu.setOutgoing();
        /*if (returnLength < 5) {
            ISOException.throwIt((short) (SW_WRONG_LENGTH | 5));
        }*/

        // Set the length of the byte array we will return. This seems a bit redundant, since we also request this
        // information from the APDU, but we can performs checks on the expected return length like this, I guess.
//        apdu.setOutgoingLength(returnLength);

        // We can now edit the buffer we initially received from the APDU to add our response.
//        buffer[0] = data[0];

        /*
        JavaCard also provides some utility methods to add larger data structures into a byte array, like the setShort()
        call under this comment, which adds the short provided in the third parameter to the byte array in the first
        parameter, starting at the position given in the second parameter.
         */
        //Util.setShort(buffer, (short) 0, (short) 25);

        // apdu.sendBytes(offset, length): Send <length> bytes off the APDU buffer starting from <offset>, note that
        // this method can be called multiple times for a single response of the card. See the JavaCard API docs:
        // javacard.framework.APDU.sendBytes()
//        apdu.sendBytes((short) 0, returnLength);
    }

    private void debugStep (APDU apdu, byte dataLength) {
        byte[] buffer = apdu.getBuffer();

        short returnLength = apdu.setOutgoing();
        if (returnLength != (short) 4) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);

        Util.setShort(buffer, (short) 0, returnLength);
        buffer[2] = (byte) 3;
        buffer[3] = (byte) 4;
        apdu.sendBytes((short) 0, returnLength);
    }

    private void handshakeStepOne (APDU apdu, byte dataLength) {
        byte[] buffer = apdu.getBuffer();
        // Check if the number of bytes in the APDU is not smaller than the minimum number required for this step.
        if (buffer[OFFSET_LC] < (byte) HANDSHAKE_ONE_INPUT_LENGTH_MIN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Extract the type of terminal we're talking to, store this to determine what protocol to switch to afterwards.
        terminalType[0] = buffer[OFFSET_CDATA];

        byte terminalSupportedVersionsLength = buffer[OFFSET_CDATA + 1];

        // Check if the supported version length fits in the data (why don't we just calculate this length value?)
        if ((byte) ((short) terminalSupportedVersionsLength + (short)(CERTIFICATE_BYTESIZE/2) + (short) 4) != (byte) dataLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Check if the list of supported versions includes our version.
        //TODO remove this check, let the terminal do this
        boolean supported = false;
        for (byte i = 0; i < terminalSupportedVersionsLength; i++) {
            if (buffer[(short) (i + OFFSET_CDATA + 2)] == VERSION_NUMBER) {
                supported = true;
            }
        }
        if (!supported) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        sequenceNumber[0] = Util.makeShort(buffer[(short) (OFFSET_CDATA + terminalSupportedVersionsLength + (short) 2)],
                buffer[(short) (OFFSET_CDATA + terminalSupportedVersionsLength + (short) 3)]);

        for (short i = 0; i < (short) (CERTIFICATE_BYTESIZE / (short) 2); i++) {
            notepad[i] = buffer[(short) (i + OFFSET_CDATA + terminalSupportedVersionsLength + (short) 4)];
        }
        

        // Send acknowledgement (1)
        short returnLength = apdu.setOutgoing();
        if (returnLength != (short) 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);

        buffer[0] = 1;
        apdu.sendBytes((short) 0, returnLength);
    }


    private void handshakeStepTwo(APDU apdu, byte dataLength ) {
        byte[] buffer = apdu.getBuffer();
        
        //Read the remainder of the certificate
        for (short i = 0; i < (short) (CERTIFICATE_BYTESIZE / (short) 2); i++) {
            notepad[(short) (i + CERTIFICATE_BYTESIZE / (short) 2)] = buffer[(short) (i + OFFSET_CDATA)];
        }
        
        // Decrypt the certificate with the master key.
        short certSize = 0;
        try {
        	rSACipher.init(masterKey, Cipher.MODE_DECRYPT);
        	certSize = rSACipher.doFinal(notepad, (short) 0, RSA_KEY_MODULUSSIZE, notepad, CERTIFICATE_BYTESIZE);
        	certSize += rSACipher.doFinal(notepad, RSA_KEY_MODULUSSIZE, RSA_KEY_MODULUSSIZE, notepad, (short)(CERTIFICATE_BYTESIZE+certSize));
        } catch (CryptoException e) {
        	ISOException.throwIt(e.getReason());
        }
        
        if (certSize != (short) (CERTIFICATE_DECRYPTED_SIZE)) {
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        
        // Hash the decrypted public key and expiration date
        short hashLength = hasher.doFinal(notepad, CERTIFICATE_BYTESIZE, (short) (RSA_KEY_BYTESIZE + DATE_BYTESIZE), notepad, (short) 0);

        if (hashLength != HASH_BYTESIZE) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }

        
        // Compare the calculated hash with the decrypted hash
        for (short i = 0; i < HASH_BYTESIZE; i++) {
            if (notepad[i] != notepad[(short) (i + CERTIFICATE_BYTESIZE + RSA_KEY_BYTESIZE + DATE_BYTESIZE)]) {
                ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
            }
        }
        
        terminalPublicKey.setModulus(notepad, CERTIFICATE_BYTESIZE, RSA_KEY_MODULUSSIZE);
        terminalPublicKey.setExponent(notepad, (short) (CERTIFICATE_BYTESIZE + RSA_KEY_MODULUSSIZE), RSA_KEY_EXPONENTSIZE);
        
        // Start building the response
        // Set APDU to response
        short returnLength = apdu.setOutgoing();
        if (returnLength != 197) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);

        // Add the card number
        for (short i = 0; i < 4; i++) {
            buffer[i] = cardNumber[i];
        }

        // Add the version number
        buffer[4] = VERSION_NUMBER;

        // Generate sequence number increment and apply it
        rngesus.generateData(notepad, (short) 0, (short) 2);
        sequenceNumber[1] = (short) (Util.makeShort(notepad[0], notepad[1]) % (short) 2^15);
        sequenceNumber[0] = (short) ((short) (sequenceNumber[0] + sequenceNumber[1]) % (short) 2^15);

        // Encrypt the sequence number and add the ciphertext to the outgoing buffer (128 bytes)
        short cipherLength = 0;
        try {
	        rSACipher.init(cardPrivateKey, Cipher.MODE_ENCRYPT);
	        Util.setShort(notepad, (short) 0, sequenceNumber[0]);
	        cipherLength = rSACipher.doFinal(notepad, (short) 0, (short) 2, notepad, (short) 2);
        } catch (CryptoException e) {
        	ISOException.throwIt(e.getReason());
        }
        for (short i = 0; i < cipherLength; i++) {
        	buffer[(short) (i + 5)] = notepad[(short) (i + 2)];
        }
        

        // Add the first 64 bytes of the certificate.
        for (short i = 0; i < (short) (CERTIFICATE_BYTESIZE/4); i++) {
            buffer[(short) (i + 5 + RSA_KEY_MODULUSSIZE)] = cardCertificate[i];
        }

        apdu.sendBytes((short) 0, returnLength);
    }

    private void handshakeStepThree(APDU apdu, byte dataLength) {
        byte[] buffer = apdu.getBuffer();

        if (dataLength != 1 || buffer[OFFSET_CDATA] != 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Set apdu to response
        short returnLength = apdu.setOutgoing();
        if (returnLength != (short) (3*(short)(CERTIFICATE_BYTESIZE/4))) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);

        //ISOException.throwIt(cardCertificate[(short) 200]);
        
        // Add the remainder of the certificate
        for (short i = 0; i < (short) (3*(short)(CERTIFICATE_BYTESIZE/4)); i++) {
            buffer[i] = cardCertificate[(short) (i + CERTIFICATE_BYTESIZE/4)];
        }

        apdu.sendBytes((short) 0, returnLength);
    }

    private void handshakeStepFour (APDU apdu, byte dataLength) {
    	byte[] buffer = apdu.getBuffer();
    	if (Util.makeShort((byte) 0, dataLength) != RSA_KEY_MODULUSSIZE) {
    		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    	}
    	
    	// Decrypt first half of symkey
    	rSACipher.init(cardPrivateKey, Cipher.MODE_DECRYPT);
    	rSACipher.doFinal(buffer, OFFSET_CDATA, RSA_KEY_MODULUSSIZE, notepad, (short) 0);
    	
    	// Send ACK
    	short returnLength = apdu.setOutgoing();
        if (returnLength != (short) 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);
        //Util.setShort(buffer, (short) 0, (short) (dataLength));//(byte) 1;
        buffer[0] = 1;
        apdu.sendBytes((short) 0, returnLength);
        return; 
    }
    
    private void handshakeStepFive(APDU apdu, byte dataLength) {
    	byte[] buffer = apdu.getBuffer();
    	if (Util.makeShort((byte) 0, dataLength) != RSA_KEY_MODULUSSIZE) {
    		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    	}
    	
    	// Decrypt first half of symkey
    	rSACipher.init(cardPrivateKey, Cipher.MODE_DECRYPT);
    	short textLength = rSACipher.doFinal(buffer, OFFSET_CDATA, RSA_KEY_MODULUSSIZE, notepad, (short) 117);
    	
    	
    	if (textLength != (short) 11) {
    		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    	}
    	
    	/*terminalPublicKey.getModulus(notepad, (short) 256);
    	terminalPublicKey.getExponent(notepad, (short) 384);
    	ISOException.throwIt(Util.makeShort(calcChecksum(notepad, (short) 256, RSA_KEY_MODULUSSIZE), 
    			calcChecksum(notepad, (short) 384, RSA_KEY_EXPONENTSIZE)));*/
    	
    	try {
    		rSACipher.init(terminalPublicKey, Cipher.MODE_DECRYPT);
    		textLength = rSACipher.doFinal(notepad, (short) 0, RSA_KEY_MODULUSSIZE, notepad, RSA_KEY_MODULUSSIZE);
    	} catch (CryptoException e) {
        	ISOException.throwIt(e.getReason());
        }
    	
    	if (textLength != (short) 18) {
    		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    	}
    	
    	symmetricKey.setKey(notepad, (short) RSA_KEY_MODULUSSIZE);
    	// ISOException.throwIt((short) calcChecksum(notepad, RSA_KEY_MODULUSSIZE, (short) 16));
    	
    	// Prepare response; card will respond with a symmetric encrypted (aesKey) OK
        short returnLength = apdu.setOutgoing();
        if (returnLength !=  AES_KEY_BYTESIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);

        short incremented = (short) ((short) (sequenceNumber[0] + 3*sequenceNumber[1])%(short) (2^15));
        Util.setShort(notepad,(short)0,incremented);
        for (short i = 2; i < AES_KEY_BYTESIZE; i++) {
        	notepad[i] = (byte) 0;
        }
        
        
        try {
        	aESCipher.init(symmetricKey,Cipher.MODE_ENCRYPT);
	        textLength = aESCipher.doFinal(notepad, (short) 0, AES_KEY_BYTESIZE, buffer, (short) 0);
	        //ISOException.throwIt(textLength);
        } catch (CryptoException e) {
        	ISOException.throwIt(e.getReason());
        }
        
        // Set APDU to response
        apdu.sendBytes((short) 0, returnLength);
    }
    
    /*private void handshakeStepFour (APDU apdu, byte dataLength) {
        byte[] buffer = apdu.getBuffer();

        if (dataLength != (short) (AES_KEY_BYTESIZE + 2)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Decrypt using private key and public terminal key
        for (byte i = 0; i<(short) (AES_KEY_BYTESIZE+2); i++){
            notepad[i] = buffer[OFFSET_CDATA+2];
        }

        rSACipher.init(cardPrivateKey,Cipher.MODE_DECRYPT);
        rSACipher.doFinal(notepad,(short)0,(short) (AES_KEY_BYTESIZE+2), notepad, (short) (AES_KEY_BYTESIZE+2));

        rSACipher.init(terminalPublicKey,Cipher.MODE_DECRYPT);
        rSACipher.doFinal(notepad,(short)0,(short) (AES_KEY_BYTESIZE+2), notepad, (short) (AES_KEY_BYTESIZE+2));

        // Check if sequence number is correct
        short receivedSequence = Util.makeShort(notepad[AES_KEY_BYTESIZE], notepad[(short) (AES_KEY_BYTESIZE+1)]);

        if (receivedSequence != (short) ((short) (sequenceNumber[0] + 2*sequenceNumber[1])%(short) (2^15))){
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // Store symmetric key
        symmetricKey.setKey(notepad, (short) 0);

        // Prepare response; card will respond with a symmetric encrypted (aesKey) OK
        short returnLength = apdu.setOutgoing();
        if (returnLength != (short) ((short) 7 + CERTIFICATE_BYTESIZE)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);

        short incremented = (short) ((short) (sequenceNumber[0] + 3*sequenceNumber[1])%(short) (2^15));
        Util.setShort(buffer,(short)0,incremented);

        aESCipher.init(symmetricKey,Cipher.MODE_ENCRYPT);
        aESCipher.doFinal(buffer, (short) 0, (short) 2, buffer, (short) 0);
        
        // Set APDU to response
        apdu.sendBytes((short) 0, returnLength);
    }*/

    private void pinStep (APDU apdu, byte dataLength) {
        byte[] buffer = apdu.getBuffer();

        // Check if encrypted message has right size
        if (Util.makeShort((byte) 0, dataLength) != (short) (AES_KEY_BYTESIZE*2)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // AES decryption
        aESCipher.init(symmetricKey, Cipher.MODE_DECRYPT);
        short pinSize = aESCipher.doFinal(buffer, OFFSET_CDATA, AES_KEY_BYTESIZE, notepad, (short) 0);
        short hashSize = aESCipher.doFinal(buffer, (short) (OFFSET_CDATA+AES_KEY_BYTESIZE), AES_KEY_BYTESIZE, notepad, pinSize);
        
        // Check if decrypted message has right size
        if (hashSize != HASH_BYTESIZE || pinSize != (short) AES_KEY_BYTESIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        	//ISOException.throwIt((short)123);
        }
        
        
        // Check if received hashed pin equals actual hashed credit
        //hasher.reset();
        hashSize = hasher.doFinal(notepad, (short) 0, (short) 4, notepad, (short) (HASH_BYTESIZE + pinSize));

        if (hashSize != HASH_BYTESIZE) {
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        
        for (short i = 0; i<HASH_BYTESIZE; i++){
            if (notepad[(short) (i + pinSize)] != notepad[(short) (i+HASH_BYTESIZE+pinSize)]){
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            	//ISOException.throwIt(Util.makeShort(notepad[(short) (i + pinSize)], notepad[(short) (i+HASH_BYTESIZE+pinSize)]));
            	//TODO uitvinden waarom dit niet werkt
            }
        }
        
        // Check if received pin equals stored pin
        // SUCCESS = 0, FAIL = 1, BLOCK = 2
        if (pin.check(notepad, (short) 0, (byte) 4)){
            notepad[0] = (byte) 0;
        } else {
            notepad[0] = (pin.getTriesRemaining() == (byte) 0) ? (byte) 2 : (byte) 1;
        }
        
        for (short i = 0; i<4; i++) {
        	notepad[(short) ( 1 + i)] = creditOnCard[i];
        }

        for (short i = 5; i < AES_KEY_BYTESIZE; i++) {
        	notepad[i] = 0;
        }
        
        // AES encryption
        aESCipher.init(symmetricKey, Cipher.MODE_ENCRYPT);
        short outLength = aESCipher.doFinal(notepad, (short) 0, (short) AES_KEY_BYTESIZE, buffer, (short) 0);

        // Set APDU to response
        short returnLength = apdu.setOutgoing();
        if (returnLength != outLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);
        //buffer[(short)0] = creditOnCard[(short)3];
        apdu.sendBytes((short) 0, returnLength);
        
    }

    private void chargeStep (APDU apdu, byte dataLength) {
        byte[] buffer = apdu.getBuffer();

        // Check if encrypted message has right size
        if (dataLength != (short) (AES_KEY_BYTESIZE*2)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // AES decryption
        aESCipher.init(symmetricKey, Cipher.MODE_DECRYPT);
        short creditSize = aESCipher.doFinal(buffer, OFFSET_CDATA, AES_KEY_BYTESIZE, notepad, (short) 0);
        short hashSize = aESCipher.doFinal(buffer, (short) (OFFSET_CDATA+AES_KEY_BYTESIZE), AES_KEY_BYTESIZE, notepad, creditSize);

        // Check if decrypted message has right size
        if (hashSize != HASH_BYTESIZE || creditSize != (short) AES_KEY_BYTESIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        

        // Check if received hashed credit equals actual hashed credit
        hasher.reset();
        hasher.doFinal(notepad, (short) 0, (short) 4, notepad, (short) (HASH_BYTESIZE + creditSize));


        
        for (short i = 0; i<HASH_BYTESIZE; i++){
            if (notepad[(short) (i+creditSize)] != notepad[(short) (i+HASH_BYTESIZE+creditSize)]){
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }
       

        // Store new credit value
        for (short i = 3; i>=(short)0; i--){
        	short temp = (short) (Util.makeShort((byte) 0, creditOnCard[i]) + Util.makeShort((byte) 0,notepad[i]));
        	if (temp >= (short) 256) {
        		creditOnCard[(short) (i-1)] = (byte) (creditOnCard[(short)(i-1)]+(byte)1);
        	}
        	creditOnCard[i] = (byte) temp;
        }

        
        // Set APDU to response
        short returnLength = apdu.setOutgoing();
        buffer[0] = (byte) 1;
        for(short i=1; i< AES_KEY_BYTESIZE; i++) {
        	buffer[i] = (byte) 0;
        }
        // AES encryption
        short outLength =(short) 0;
        try {
            aESCipher.init(symmetricKey, Cipher.MODE_ENCRYPT);
        	outLength = aESCipher.doFinal(buffer, (short) 0, (short) 16, buffer, (short) 0);
        } catch(CryptoException e) {
        	ISOException.throwIt(e.getReason());
        }

        if (returnLength != outLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);
        apdu.sendBytes((short) 0, returnLength);
    }

    private void pumpStep (APDU apdu, byte dataLength) {
        // Incoming: Transaction info -> (saldoChange, currentDate, terminalNumber, cardNumber)
        // encrypted with the privateT-key,
        // and H(Transaction Info)
        // The entire things is encrypted with the AES key
        byte[] buffer = apdu.getBuffer();
        // Check if encrypted message has right size
        if (Util.makeShort((byte) 0, dataLength) != (short) (AES_KEY_BYTESIZE + RSA_KEY_MODULUSSIZE)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // AES decryption
        aESCipher.init(symmetricKey, Cipher.MODE_DECRYPT);
        short msgSize = 0;
        while (msgSize < Util.makeShort((byte) 0, dataLength)) {
        	try {
        		msgSize += aESCipher.doFinal(buffer, (short) (OFFSET_CDATA + msgSize), AES_KEY_BYTESIZE, notepad, (short) msgSize);
        	} catch (CryptoException e) {
        		ISOException.throwIt(e.getReason());
        	}
        }
        
        if ((byte) msgSize != dataLength) {
        	ISOException.throwIt(msgSize);
        }
        
        /*
        short returnLength = apdu.setOutgoing();
        if (returnLength != (short) 256) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        apdu.setOutgoingLength(returnLength);
        for (short i = 0; i < msgSize; i++) {
        	buffer[(short) i] = notepad[(short) i];
        }
        
        apdu.sendBytes((short) 0, returnLength);
        return;  */
        
        
        // Decrypt transaction info
        rSACipher.init(terminalPublicKey,Cipher.MODE_DECRYPT);
        short transactionSize = 0;
        try {
        	transactionSize = rSACipher.doFinal(notepad, (short) 0, RSA_KEY_MODULUSSIZE, notepad, (short) (msgSize));
        } catch (CryptoException e) {
        	ISOException.throwIt(e.getReason());
        }
        //short hashSize = aESCipher.doFinal(buffer, (short) (OFFSET_CDATA+AES_KEY_BYTESIZE), AES_KEY_BYTESIZE, notepad, msgSize);

        // Check if decrypted message has right size
        if (transactionSize != TRANSACTIONINFO_BYTESIZE ) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Check if received hashed transaction equals actual hashed transaction
        hasher.doFinal(notepad, msgSize, transactionSize, notepad, (short) (msgSize+transactionSize));

        for (byte i = 0; i<HASH_BYTESIZE; i++){
            if (notepad[(short) (msgSize-HASH_BYTESIZE+i)] != notepad[(short) (msgSize+transactionSize+i)]){
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }

        //TODO check things in transactioninfo
        // Saldo - change
        byte overflow = 0;
        // Saldo change (first 4 bytes)
        for (short i = 3; i>=0; i--){
            if ((byte) (creditOnCard[i] - overflow) < (short) (notepad[(short) (msgSize+i)])){
                byte temp = (byte) (notepad[(short) (msgSize+i)] - creditOnCard[i]); 
                
            	creditOnCard[i] = (byte) (255 - temp - overflow);
            			//(short) (10 - notepad[(short) (msgSize+HASH_BYTESIZE*2+i)] - overflow);
                overflow = 1;
            } else {
                creditOnCard[i] -= (notepad[(short) (msgSize+i)] + overflow);
                overflow = 0;
            }
        }
        if (overflow == (byte) 1) {
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Outgoing: The original transaction info, encrypted with privateT, also encrypted with privateC
        rSACipher.init(cardPrivateKey,Cipher.MODE_ENCRYPT);
        short cipherSize = rSACipher.doFinal(notepad, (short) 0, (short) 117, notepad, (short) (RSA_KEY_BYTESIZE * 2));
        cipherSize += rSACipher.doFinal(notepad, (short) 117, (short) 11, notepad, (short) ((RSA_KEY_BYTESIZE * 2) +128));
        
        // AES encryption
        aESCipher.init(symmetricKey, Cipher.MODE_ENCRYPT);
        short outLength = 0;
        while (outLength != cipherSize) {
        	outLength += aESCipher.doFinal(notepad, (short) ((RSA_KEY_BYTESIZE * 2) + outLength), AES_KEY_BYTESIZE, buffer, (short) (0 + outLength));
        }

        short returnLength = apdu.setOutgoing();
        if (returnLength != outLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);

        // Set APDU to response
        apdu.sendBytes((short) 0, returnLength);
    }

    private void personalizeStepOne (APDU apdu, byte dataLength) {
        byte[] buffer = apdu.getBuffer();
        // Modulus (128 bytes)
        cardPrivateKey.setModulus(buffer, OFFSET_CDATA, RSA_KEY_MODULUSSIZE);
        
        
        // Response (1 byte)
        
        short returnLength = apdu.setOutgoing();
        if (returnLength != (short) 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);
        //Util.setShort(buffer, (short) 0, (short) (dataLength));//(byte) 1;
        buffer[0] = 1;
        apdu.sendBytes((short) 0, returnLength);
        return; 
    }

    private void personalizeStepTwo (APDU apdu, byte dataLength) {
    	byte[] buffer = apdu.getBuffer();

    	// Private Exponent (variable, max 128 bytes)
    	try {
    		cardPrivateKey.setExponent(buffer, OFFSET_CDATA, Util.makeShort((byte) 0, dataLength));
    	} catch (CryptoException e) {
        	ISOException.throwIt(e.getReason());
        }
    	// Response (1 byte)
        short returnLength = apdu.setOutgoing();
        if (returnLength != (short) 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);
        //Util.setShort(buffer, (short) 0, (short) (dataLength));//(byte) 1;
        buffer[0] = 1;
        apdu.sendBytes((short) 0, returnLength);
        return;
    }
    
    private void personalizeStepThree (APDU apdu, byte dataLength) {
        byte[] buffer = apdu.getBuffer();
        // Master key (128 bytes)
        masterKey.setExponent(buffer, (short) (OFFSET_CDATA + RSA_KEY_MODULUSSIZE), RSA_KEY_EXPONENTSIZE);
        masterKey.setModulus(buffer, OFFSET_CDATA, RSA_KEY_MODULUSSIZE);
        
        // Partial certificate (64 bytes)
        for (short i = 0; i < (short) (CERTIFICATE_BYTESIZE / 4); i++) {
            cardCertificate[i] = buffer[(short) (OFFSET_CDATA + i + RSA_KEY_BYTESIZE)];
        }

        //Pin (4 bytes), Cardnumber (4 bytes)
        pin.update(buffer, (short) (OFFSET_CDATA + RSA_KEY_BYTESIZE + (short) (CERTIFICATE_BYTESIZE / 4)), (byte) 4);

        for (short i = 0; i < 4; i++) {
            cardNumber[i] = buffer[(short) (OFFSET_CDATA + RSA_KEY_BYTESIZE + (short) (CERTIFICATE_BYTESIZE /4) + i + 4)];
        }
        
        // Response (1 byte)
        short returnLength = apdu.setOutgoing();
        if (returnLength != (short) 130) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);
        //buffer[0] = (byte) 1;
        
        masterKey.getModulus(notepad, (short) 0);
        buffer[0] = calcChecksum(notepad, (short) 0, RSA_KEY_MODULUSSIZE);
        masterKey.getExponent(notepad, (short) 0);
        buffer[1] = calcChecksum(notepad, (short) 0, RSA_KEY_EXPONENTSIZE);
        masterKey.getModulus(buffer, (short) 2);
        apdu.sendBytes((short) 0, returnLength);
    }

    private void personalizeStepFour (APDU apdu, byte dataLength) {
        byte[] buffer = apdu.getBuffer();
        // Partial Certificate (192 bytes)
        for (short i = 0; i < (short) (3*(short)(CERTIFICATE_BYTESIZE/4)); i++) {
            cardCertificate[(short) (i + (CERTIFICATE_BYTESIZE/4))] = buffer[(short) (OFFSET_CDATA + i)];
        }

        // Response (1 byte)
        short returnLength = apdu.setOutgoing();
        if (returnLength != (short) 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);
        buffer[0] = (byte) 1;
        //buffer[0] = (byte) (CERTIFICATE_BYTESIZE - (CERTIFICATE_BYTESIZE / 4));
        apdu.sendBytes((short) 0, returnLength);
    }
    
    private byte calcChecksum (byte[] inBuffer, short offset, short length) {
    	byte checksum = 0;
    	for (short i = 0; i < length; i++) {
    		checksum += inBuffer[(short) (i + offset)];
    	}
    	return checksum;
    }

    /*private void respond() { I think this is javacard 2.2.2

    }*/

    /**
     * Called by the JavaCard OS when the applet is deselected. Can be overridden if we have to perform some cleanup.
     * Note that the deselect() of app A is called before the select() of app B.
     */
    /*public void deselect() {

    }*/

}
