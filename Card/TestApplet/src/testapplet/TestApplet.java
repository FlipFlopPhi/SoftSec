package testapplet;

import javacard.framework.*;

public class TestApplet extends Applet implements ISO7816 {


    public TestApplet() {
        register();
    }

    /*public void deselect() {

    }*/

    /*public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        return null;
    }*/

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new TestApplet();
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte dataLength = buffer[OFFSET_CDATA];
	byte[] data = new byte[dataLength];
	byte returnLength = buffer[(short)(OFFSET_CDATA + dataLength+1)];
	
	for (short i = 0; i < dataLength; i++) {
		data[i] = buffer[(short)(OFFSET_CDATA + i+1)];
	}

        // process() is also called with the APDU that selected this applet in the first place,
        // ignore that APDU, it has done what it had to do.
        if (selectingApplet()) {
            return;
        }
	short le = apdu.setOutgoing();
        if (le < 5) {
            ISOException.throwIt((short) (SW_WRONG_LENGTH | 5));
        }

        apdu.setOutgoingLength(returnLength);
	buffer[0] = data[0];
        apdu.sendBytes((short) 0, returnLength);
    }

    public boolean select() {
        return true;
    }
}
