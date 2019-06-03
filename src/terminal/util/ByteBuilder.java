/**
 * 
 */
package terminal.util;

/**
 * @author pspaendonck
 *
 */
public class ByteBuilder {

	public final byte[] array;
	public final int length;
	private int top = 0;
	
	public ByteBuilder(int arrayLength) {
		array = new byte[arrayLength];
		length = arrayLength;
	}

	public ByteBuilder add(byte[] date) {
		for(int i=0; i<date.length; i++,top++) {
			array[top] = date[i];
		}
		return this;
	}

	public ByteBuilder add(int integer) {
		return this.add(BytesHelper.fromInt(integer));
	}
	
	
}
