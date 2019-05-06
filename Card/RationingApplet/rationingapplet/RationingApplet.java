package rationingapplet;

import javacard.framework.*;


public class RationingApplet extends Applet implements ISO7816 {
    // Data definitions
    //private byte someData[];
    private short oldState[];
    private byte sequenceNumber[], terminalType[], terminalSupportedVersions[], ;
    private static short CERTIFICATE_BYTESIZE = 130;

    public RationingApplet() {
        //Do data allocations here.
        //someData = new byte[10]; // persistent data, stays on the card between resets
        //someData = JCSystem.makeTransientByteArray((short) 10, JCSystem.CLEAR_ON_RESET); // transient data, is cleared when the card is removed from the terminal.

        oldState = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
        sequenceNumber = JCSystem.MakeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
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
        byte dataLength = buffer[OFFSET_CDATA];

        short terminalState = Util.makeShort(buffer[OFFSET_P1], buffer[OFFSET_P2]);

        switch(terminalState) {
            case 1:
                if (oldState[0] != (short) 0) {
                    throw new CardException((short) 0); // Maybe we should define a StateException or something, or can JavaCard not handle that?
                }
                buffer = handshakeStepOne(buffer);

                break;
            default:
                throw new CardException((short) 0); // No idea what value should be passed
                break;
        }



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
        if (selectingApplet()) {
            return;
        }

        // Set the apdu to outgoing, discards any remaining input data. This also returns the expected output length.
        // I'm not sure what happens if there is no expected response, I expect returnLength to be 0 then (?)
        short returnLength = apdu.setOutgoing();
        /*if (returnLength < 5) {
            ISOException.throwIt((short) (SW_WRONG_LENGTH | 5));
        }*/

        // Set the length of the byte array we will return. This seems a bit redundant, since we also request this
        // information from the APDU, but we can performs checks on the expected return length like this, I guess.
        apdu.setOutgoingLength(returnLength);

        // We can now edit the buffer we initially received from the APDU to add our response.
        buffer[0] = data[0];

        /*
        JavaCard also provides some utility methods to add larger data structures into a byte array, like the setShort()
        call under this comment, which adds the short provided in the third parameter to the byte array in the first
        parameter, starting at the position given in the second parameter.
         */
        //Util.setShort(buffer, (short) 0, (short) 25);

        // apdu.sendBytes(offset, length): Send <length> bytes off the APDU buffer starting from <offset>, note that
        // this method can be called multiple times for a single response of the card. See the JavaCard API docs:
        // javacard.framework.APDU.sendBytes()
        apdu.sendBytes((short) 0, returnLength);
    }

    private byte[] HandshakeStepOne () {

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