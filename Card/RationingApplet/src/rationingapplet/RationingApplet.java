package rationingapplet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class RationingApplet extends Applet implements ISO7816 {
    // Data definitions
    //private byte someData[];
    private byte notepad[];
    private short oldState[];
    private boolean isPersonalized;
    private short sequenceNumber[];
    private byte terminalType[];
    private byte terminalNumber[];
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
    private static short DATETIME_BYTESIZE = 4;
    private static short IDENTIFIER_BYTESIZE = 4;
    private static short TRANSACTIONINFO_BYTESIZE = 16;
    private static short CERTIFICATE_BYTESIZE = 256;
    private static short CERTIFICATE_DECRYPTED_SIZE = 153;
    private static short HANDSHAKE_ONE_INPUT_LENGTH_MIN = 133;
    private static short NOTEPAD_SIZE = 520;
    private static byte VERSION_NUMBER = 1;

    public RationingApplet() {
        //520 bytes of memory that should be used as temporary storage of byte arrays instead of defining different arrays for every single thing.
        notepad = JCSystem.makeTransientByteArray((short) NOTEPAD_SIZE, JCSystem.CLEAR_ON_RESET);

        // public master key, used to decrypt certificates
        masterKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
        
        // Card specific information: private key and related certificate, identifing cardnumber, the amount of credit (default 100) and whether the card has been personalized (all this info has been set)
        cardPrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);
        cardCertificate = new byte[CERTIFICATE_BYTESIZE];
        cardNumber = new byte[IDENTIFIER_BYTESIZE];
    	creditOnCard = new byte[4];
    	for(short i=0; i<3; i++) {
    		creditOnCard[i] = (byte) 0;
    	}
    	creditOnCard[(short) 3] = (byte) 100;
		isPersonalized = false;

        // Pin: max tries = 4, max size = 4
        pin = new OwnerPIN((byte) 4, (byte) 4);

        // Cipher instances: RSA, AES and MD5
        rSACipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        aESCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        hasher = MessageDigest.getInstance(MessageDigest.ALG_MD5, false);
        
        // Random number generator
        rngesus = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        // Information specific for a single run of the protocol: The last state entered and the sequence number
        oldState = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
        sequenceNumber = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET); // The sequence number and how much is added per increment.

        // Terminal specific information, changes for each run of the protocol
        terminalType = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        terminalNumber = JCSystem.makeTransientByteArray(IDENTIFIER_BYTESIZE, JCSystem.CLEAR_ON_RESET);
        terminalPublicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);

		// Temporary AES key, changes for each run of the protocol
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
        
        // process() is also run for the APDU selecting our applet, ignore this execution.
        if (selectingApplet()) {
            return;
        }

        // Extract what state the terminal wants to enter
        short terminalState = Util.makeShort(buffer[OFFSET_P1], buffer[OFFSET_P2]);

        // Enter the requested state, only if the state entered before that is correct.
        switch(terminalState) {
            case 1:
                if (oldState[0] != (short) 0 && oldState[0] != (short) 11) { 
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
            	// The following states can only be executed (in their entirety) once
                if (oldState[0] != (short) 0 || isPersonalized) {
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                }
                personalizeStepOne(apdu, dataLength);

                break;
            case 9:
                if (oldState[0] != (short) 8 || isPersonalized) {
                    //ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                	ISOException.throwIt(oldState[0]);
                }
                personalizeStepTwo(apdu, dataLength);

                break;
            case 10:
                if (oldState[0] != (short) 9 || isPersonalized) {
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                }
                personalizeStepThree(apdu, dataLength);

                break;
            case 11:
            	if (oldState[0] != (short) 10 || isPersonalized) {
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);            		
            	}
            	personalizeStepFour(apdu, dataLength);
            	isPersonalized = true;
            	break;
            default:

                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                break;
        }
        oldState[0] = terminalState;
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
        boolean supported = false;
        for (byte i = 0; i < terminalSupportedVersionsLength; i++) {
            if (buffer[(short) (i + OFFSET_CDATA + 2)] == VERSION_NUMBER) {
                supported = true;
            }
        }
        if (!supported) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Extract the sequence number from the input
        sequenceNumber[0] = Util.makeShort(buffer[(short) (OFFSET_CDATA + terminalSupportedVersionsLength + (short) 2)],
                buffer[(short) (OFFSET_CDATA + terminalSupportedVersionsLength + (short) 3)]);

        // Read the first half of the terminal certificate
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
        
        // Check if the decrypted certificate is of the correct length
        if (certSize != (short) (CERTIFICATE_DECRYPTED_SIZE)) {
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Extract the Terminal Number from the decrypted certificate
        for(short i = 0; i < IDENTIFIER_BYTESIZE; i++) {
        	terminalNumber[i] = notepad[(short) (CERTIFICATE_BYTESIZE + RSA_KEY_BYTESIZE + i)];
        }
        
        // Hash the decrypted public key, terminalnumber and expiration date
        short hashLength = hasher.doFinal(notepad, CERTIFICATE_BYTESIZE, (short) (RSA_KEY_BYTESIZE + IDENTIFIER_BYTESIZE + DATE_BYTESIZE), notepad, (short) 0);

        if (hashLength != HASH_BYTESIZE) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }

        
        // Compare the calculated hash with the decrypted hash
        for (short i = 0; i < HASH_BYTESIZE; i++) {
            if (notepad[i] != notepad[(short) (i + CERTIFICATE_BYTESIZE + RSA_KEY_BYTESIZE + IDENTIFIER_BYTESIZE + DATE_BYTESIZE)]) {
                ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
            }
        }
        
        // Save the terminal public key from the decrypted certificate
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
        for (short i = 0; i < IDENTIFIER_BYTESIZE; i++) {
            buffer[i] = cardNumber[i];
        }

        // Add the version number
        buffer[4] = VERSION_NUMBER;

        // Generate sequence number increment and apply it
        rngesus.generateData(notepad, (short) 0, (short) 2);
        sequenceNumber[1] = Util.makeShort(notepad[0], notepad[1]);
        if (sequenceNumber[1] <(short) 0) {
    		sequenceNumber[1] += (short) 32768; // Make sure seqNum[1] is mod 2^15
    	}
        incrementSeqNum();
        
        // Encrypt the sequence number and add the resulting ciphertext to the outgoing buffer (128 bytes)
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

        // Transmit
        apdu.sendBytes((short) 0, returnLength);
    }

    private void handshakeStepThree(APDU apdu, byte dataLength) {
        byte[] buffer = apdu.getBuffer();

        // We should only recieve a single 1 in this step.
        if (dataLength != 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Start building the response
        // Set apdu to response
        short returnLength = apdu.setOutgoing();
        if (returnLength != (short) (3*(short)(CERTIFICATE_BYTESIZE/4))) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);

        // Add the remainder of the certificate
        for (short i = 0; i < (short) (3*(short)(CERTIFICATE_BYTESIZE/4)); i++) {
            buffer[i] = cardCertificate[(short) (i + CERTIFICATE_BYTESIZE/4)];
        }

        // Transmit
        apdu.sendBytes((short) 0, returnLength);
    }

    private void handshakeStepFour (APDU apdu, byte dataLength) {
    	byte[] buffer = apdu.getBuffer();
    	
    	// In these steps we recieve the AES symmetric key, which is too large for a single APDU, so read one half first.
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
        buffer[0] = 1;
        apdu.sendBytes((short) 0, returnLength);
        return; 
    }
    
    private void handshakeStepFive(APDU apdu, byte dataLength) {
    	byte[] buffer = apdu.getBuffer();
    	if (Util.makeShort((byte) 0, dataLength) != RSA_KEY_MODULUSSIZE) {
    		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    	}
    	
    	// Decrypt second half of symkey, place it behind the decrypted first half.
    	rSACipher.init(cardPrivateKey, Cipher.MODE_DECRYPT);
    	short textLength = rSACipher.doFinal(buffer, OFFSET_CDATA, RSA_KEY_MODULUSSIZE, notepad, (short) 117);
    	
    	// The total length should now be 128 bytes.
    	if (textLength != (short) 11) {
    		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    	}
    	
    	// Decrypt the symkey+seqnum with the public key of the terminal
    	try {
    		rSACipher.init(terminalPublicKey, Cipher.MODE_DECRYPT);
    		textLength = rSACipher.doFinal(notepad, (short) 0, RSA_KEY_MODULUSSIZE, notepad, RSA_KEY_MODULUSSIZE);
    	} catch (CryptoException e) {
        	ISOException.throwIt(e.getReason());
        }
    	
    	if (textLength != (short) 18) {
    		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    	}
    	
    	// Set the AES key
    	symmetricKey.setKey(notepad, (short) RSA_KEY_MODULUSSIZE);
    	
    	// Check if the incremented sequence number sent by the terminal is correct.
    	incrementSeqNum();
    	if (Util.makeShort(notepad[(short) (RSA_KEY_MODULUSSIZE + AES_KEY_BYTESIZE)], 
    			notepad[(short) (RSA_KEY_MODULUSSIZE + AES_KEY_BYTESIZE + 1)]) != sequenceNumber[0]) {
    		ISOException.throwIt(ISO7816.SW_FILE_INVALID);
    	}
    	
    	// Increment the sequence number again, to be sent back.
    	incrementSeqNum();
    	
    	// Prepare response; card will respond with a symmetric encrypted (aesKey) OK
    	// Set APDU to outgoing
        short returnLength = apdu.setOutgoing();
        if (returnLength !=  AES_KEY_BYTESIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);

        // Prepare the sequence number for encryption.
        Util.setShort(notepad,(short)0,sequenceNumber[0]);
        for (short i = 2; i < AES_KEY_BYTESIZE; i++) {
        	notepad[i] = (byte) 0;
        }
        
        // Encrypt the sequence number into the outgoing buffer.
        try {
        	aESCipher.init(symmetricKey,Cipher.MODE_ENCRYPT);
	        textLength = aESCipher.doFinal(notepad, (short) 0, AES_KEY_BYTESIZE, buffer, (short) 0);
	        //ISOException.throwIt(textLength);
        } catch (CryptoException e) {
        	ISOException.throwIt(e.getReason());
        }
        
        // Transmit
        apdu.sendBytes((short) 0, returnLength);
    }
    

    private void pinStep (APDU apdu, byte dataLength) {
        byte[] buffer = apdu.getBuffer();

        // Check if encrypted message has right size
        if (Util.makeShort((byte) 0, dataLength) != (short) (AES_KEY_BYTESIZE*2)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // AES decryption of the pin and hash
        aESCipher.init(symmetricKey, Cipher.MODE_DECRYPT);
        short pinSize = aESCipher.doFinal(buffer, OFFSET_CDATA, AES_KEY_BYTESIZE, notepad, (short) 0);
        short hashSize = aESCipher.doFinal(buffer, (short) (OFFSET_CDATA+AES_KEY_BYTESIZE), AES_KEY_BYTESIZE, notepad, pinSize);
        
        // Check if decrypted messages have the right size
        if (hashSize != HASH_BYTESIZE || pinSize != (short) AES_KEY_BYTESIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        	//ISOException.throwIt((short)123);
        }
        
        // Check if received hash is the hashed pin.
        hashSize = hasher.doFinal(notepad, (short) 0, (short) 4, notepad, (short) (HASH_BYTESIZE + pinSize));

        if (hashSize != HASH_BYTESIZE) {
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        for (short i = 0; i<HASH_BYTESIZE; i++){
            if (notepad[(short) (i + pinSize)] != notepad[(short) (i+HASH_BYTESIZE+pinSize)]){
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }
        
        // Check if received pin equals stored pin
        // SUCCESS = 0, FAIL = 1, BLOCK = 2
        if (pin.check(notepad, (short) 0, (byte) 4)){
            notepad[0] = (byte) 0;
        } else {
            notepad[0] = (pin.getTriesRemaining() == (byte) 0) ? (byte) 2 : (byte) 1;
        }
        
        // Prepare the reponse
        // Load the credit into the notepad
        for (short i = 0; i<4; i++) {
        	if (notepad[0] == (byte) 0) {
        		notepad[(short) ( 1 + i)] = creditOnCard[i];
        	}
        	else {
        		notepad[(short) ( 1 + i)] = (byte) 0;
        	}
        }

        // Set the other bytes in notepad <16 to 0
        for (short i = 5; i < AES_KEY_BYTESIZE; i++) {
        	notepad[i] = 0;
        }
        
        // AES encrypt the credit in to the outgoing buffer
        aESCipher.init(symmetricKey, Cipher.MODE_ENCRYPT);
        short outLength = aESCipher.doFinal(notepad, (short) 0, (short) AES_KEY_BYTESIZE, buffer, (short) 0);

        // Set APDU to response and transmit
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
        
        // Decrypt transaction info
        rSACipher.init(terminalPublicKey,Cipher.MODE_DECRYPT);
        short transactionSize = 0;
        try {
        	transactionSize = rSACipher.doFinal(notepad, (short) 0, RSA_KEY_MODULUSSIZE, notepad, (short) (msgSize));
        } catch (CryptoException e) {
        	ISOException.throwIt(e.getReason());
        }
        
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

        // Compare the terminalnumber from the certificate with the terminalnumber in the transactioninfo
        for (short i = 0; i < IDENTIFIER_BYTESIZE; i++) {
        	if (terminalNumber[i] != notepad[(short) (msgSize + DATETIME_BYTESIZE + 4 + i)]) {
        		//ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        	}
        }
        
        //	Compare the cardnumber on the card with the cardnumber in the transactioninfo
        for (short i = 0; i < IDENTIFIER_BYTESIZE; i++) {
        	if (cardNumber[i] != notepad[(short) (msgSize + DATETIME_BYTESIZE + IDENTIFIER_BYTESIZE + 4 + i)]) {
        		ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        	}
        }
        
        // Decreae the credit on the card
        short overflow = 0;
        // Saldo change (first 4 bytes)
        for (short i = 3; i>=0; i--){
            // If the byte of stored credit is smaller than the requested decrease, we take an overflow from the next byte.
        	if ((short) (Util.makeShort((byte) 0, creditOnCard[i]) - overflow) < Util.makeShort((byte) 0, notepad[(short) (msgSize+i)])) {
            	byte temp = (byte) (notepad[(short) (msgSize+i)] - creditOnCard[i]); 
                
            	creditOnCard[i] = (byte) (256 - temp - overflow);
                overflow = 1;
            } else {
                creditOnCard[i] -= (notepad[(short) (msgSize+i)] + overflow);
                overflow = 0;
            }
        }
        // If we end with an overflow, the requested decrease is larger than the credit on the card, since we cant go negative, fail.
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

        // Transmit
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

        for (short i = 0; i < IDENTIFIER_BYTESIZE; i++) {
            cardNumber[i] = buffer[(short) (OFFSET_CDATA + RSA_KEY_BYTESIZE + (short) (CERTIFICATE_BYTESIZE /4) + i + 4)];
        }
        
        // Response (1 byte)
        short returnLength = apdu.setOutgoing();
        if (returnLength != (short) 130) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(returnLength);
        
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
        apdu.sendBytes((short) 0, returnLength);
    }
    
    private byte calcChecksum (byte[] inBuffer, short offset, short length) {
    	byte checksum = 0;
    	for (short i = 0; i < length; i++) {
    		checksum += inBuffer[(short) (i + offset)];
    	}
    	return checksum;
    }
    
    private void incrementSeqNum () {
    	//sequenceNumber = [seqNum, increment]
    	sequenceNumber[0] = (short) (sequenceNumber[0] + sequenceNumber[1]);
    	if (sequenceNumber[0] <(short) 0) {
    		sequenceNumber[0] += (short) 32768;
    	}
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
