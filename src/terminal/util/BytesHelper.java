package terminal.util;

import java.nio.ByteBuffer;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Calendar;
import java.util.TimeZone;

/**
 * Utility class used to convert data types to byte arrays and vice versa
 * @author Vizu
 *
 */
public final class BytesHelper {
	

	public final static int STARTING_YEAR = 2019;
	
	private BytesHelper() {} //this is so 
	
	public static int toInt( byte[] bytes ) {
		byte[] bytes2;
		if (bytes.length != 4) {
			bytes2 = new byte[4];
			for(int i=0; i<bytes.length; i++)
				bytes2[3-i] = bytes[bytes.length-i-1];
		} else
			bytes2 = bytes;
	    return ByteBuffer.wrap(bytes2).getInt();
	}

	public static short toShort(byte[] bytes) {
		return ByteBuffer.wrap(bytes).getShort();
	}

	public static byte[] fromShort(short value) {
		return ByteBuffer.allocate(Short.BYTES).putShort(value).array();
	}
	
	public static byte[] fromDate(Calendar calendar) {
		int y = calendar.get(Calendar.YEAR);
		int m = calendar.get(Calendar.MONTH);
		int d = calendar.get(Calendar.DAY_OF_MONTH);
		short temp = (short) ((y-STARTING_YEAR) << 9);
		temp += m << 5;
		temp += d;
		
		return fromShort(temp); // yyyyyyym mmmddddd
	}
	
	public static byte[] fromDate() {
		Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		return fromDate(calendar);
	}
	
	public static byte[] fromPreciseDate() {
		byte[] date = Arrays.copyOf(fromDate(), 4);
		Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		date[1] = (byte) calendar.get(Calendar.MINUTE);
		date[0] = (byte) calendar.get(Calendar.HOUR_OF_DAY);
		
		return date; //yyyyyyym mmmddddd XX------ XXXhhhhh 
	}

	public static byte[] fromInt(int integer) {
		return ByteBuffer.allocate(Integer.BYTES).putInt(integer).array();
	}

	public static byte[] fromPrivateKey(RSAPrivateKey privateKey) {
		System.out.println(privateKey.getModulus().compareTo( privateKey.getPrivateExponent()));
		byte[] exponent = privateKey.getPrivateExponent().toByteArray();
		System.out.println(exponent.length);
		byte[] key = Arrays.copyOf(privateKey.getModulus().toByteArray(),128+exponent.length);
		for(int i=0; i<exponent.length; i++) {
			key[128+i] = exponent[i];
		}
		System.out.println(key.length);
		return key;
	}
}
  