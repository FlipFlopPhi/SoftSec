/**
 * 
 */
package terminal.util;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

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

	public ByteBuilder add(byte[] data) {
		return this.add(data, 0, data.length);
	}
	public ByteBuilder add(byte[] data, int from, int to) {
		for(int i=from; i<data.length &i<to; i++,top++) {
			array[top] = data[i];
		}
		return this;
	}

	public ByteBuilder add(int integer) {
		return this.add(BytesHelper.fromInt(integer));
	}
	
	public ByteBuilder add(short value) {
		return this.add(BytesHelper.fromShort(value));
	}
	
	public ByteBuilder add(byte b) {
		array[top++] = b;
		return this;
	}

	public ByteBuilder addPublicRSAKey(RSAPublicKey rsaPublicKey) {
		return this.add(Arrays.copyOfRange(rsaPublicKey.getModulus().toByteArray(),1,1+Util.MODULUS_LENGTH))
				.add(Arrays.copyOf(rsaPublicKey.getPublicExponent().toByteArray(),3));
	}
	
	public int getTop() {return top;}


	
}
