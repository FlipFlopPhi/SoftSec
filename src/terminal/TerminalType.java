/**
 * 
 */
package terminal;

/**
 * @author pspaendonck
 *
 */
public enum TerminalType {
	CHARGER((byte)1)
	, PUMP((byte)2);

	private final byte b;
	
	private TerminalType(byte b) {
		this.b=b;
	}
	public byte getByte() {
		return b;
	}

}
