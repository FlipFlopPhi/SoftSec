package ratooningsystem;

import javax.smartcardio.*;
import java.util.Arrays;
import java.util.List;

public class Main {

    public final byte[] APP_ID = {(byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78, (byte) 0x90, (byte) 0xab, };
    // hardcoded APDU that selects APP_ID from the card os.
    public final CommandAPDU SELECT_APDU = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, APP_ID);

    public Main() {
        TerminalFactory tf = TerminalFactory.getDefault();
        CardTerminals cts = tf.terminals();
        try {
            List<CardTerminal> ctl = cts.list(CardTerminals.State.CARD_PRESENT);

            while(true) {
                for (CardTerminal ct : ctl) {
                    if (!ct.isCardPresent()){

                        continue;
                    }
                    Card c = ct.connect("*");

                    // Select our applet
                    CardChannel cardChan = c.getBasicChannel();
                    ResponseAPDU resp = cardChan.transmit(SELECT_APDU);
                    if (resp.getSW() != 0x9000) {
                        System.out.println(resp.getSW());
                        throw new Exception("Select failed");
                    }

                    // Just send some dumb test message
                    for(byte i = 1; i < 126; i++) {
                    	resp = cardChan.transmit(new CommandAPDU((byte) 0xD0, (byte) 0x00, (byte) 0x00, (byte) 0x00, new byte[] {1, i, 1}));
                    	byte[] respData= resp.getBytes();
                    	System.out.println(Arrays.toString(respData));
											System.out.println(resp.toString());
                    	System.out.println("Dit had een echo moeten zijn van" + i);
                    }
                }
            }
        } catch (CardException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }


    }



    public static void main (String[] args) {
        Main main = new Main();
    }
}
