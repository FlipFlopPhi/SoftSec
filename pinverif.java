
package Applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;

public class pinverif extends Applet {

    /* constants declaration */

    // codes of INS byte in the command APDU header
    final static byte VERIFY = (byte) 0x20;
    
    final static byte  UPDATE_PIN = (byte) 0x70;

    // maximum number of incorrect tries before the
    	// PIN is blocked
    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    // maximum size PIN
    final static byte MAX_PIN_SIZE = (byte) 0x08;

    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6300;
    

    /* instance variables declaration */
    OwnerPIN pin;

    byte IS_VALIDATED;
	
        public static void install(byte[] bArray, short bOffset, byte bLength) {
        // create a Wallet applet instance
        new pinverif(bArray, bOffset, bLength);
    } // end of install method

    @Override
    public boolean select() {

        // The applet declines to be selected
        // if the pin is blocked.
        if (pin.getTriesRemaining() == 0) {
            return false;
        }

        return true;

    }// end of select method

    @Override
    public void deselect() {

        // reset the pin value
        pin.reset();

    }

    @Override
    public void process(APDU apdu) {


        byte[] buffer = apdu.getBuffer();
        // check SELECT APDU command

        if (apdu.isISOInterindustryCLA()) {
            if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case VERIFY:
                verify(apdu);
                return;
            case UPDATE_PIN:
            	update_pin(apdu);
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

    }     
    
    private void verify(APDU apdu) {

        byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // check pin
        // the PIN data is read into the APDU buffer
        // at the offset ISO7816.OFFSET_CDATA
        // the PIN data length = byteRead
        if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }

    } // end of verify method
    
private void update_pin(APDU apdu) {
    	
    	
        byte[] buffer = apdu.getBuffer();        
        
        byte[] oldPIN, newPIN;
        oldPIN= new byte[MAX_PIN_SIZE];
        newPIN= new byte[MAX_PIN_SIZE];
               	
        byte oldPinLen,newPinLen,i;
        oldPinLen = 1;        
        newPinLen = 1; 
        
        i= ISO7816.OFFSET_CDATA;
        
        while (buffer[i]!= 0x0A) {
        	oldPIN[oldPinLen]= buffer[i];
        	oldPinLen++;
        	i++;
        }
        i++;
        while (buffer[i]!= 0x0A) {
        	newPIN[newPinLen]= buffer[i];
        	newPinLen++;
        	i++;
        }
        

        if (pin.check(oldPIN, (byte)1 , (byte) (oldPinLen-1)) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
       
        
        	pin.update(newPIN, (short) 1 , (byte)(newPinLen-1));
        
    } // end of validate method


        if (pin.check(buffer, (byte)3 , (byte) oldpinLen) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
       
        
        	pin.update(newpinVal, (short) ((short) 3 + oldpinLen) , (byte) newpinLen);
        
    } // end of validate method
} 



