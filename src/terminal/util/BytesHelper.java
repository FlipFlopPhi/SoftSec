package terminal.util;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Calendar;
import java.util.TimeZone;

public final class BytesHelper {
	

	public final static int STARTING_YEAR = 2020;
	
	private BytesHelper() {} //this is so 
	
	public static int toInt( byte[] bytes ) {
	    int result = 0;
	    for (int i=0; i<4; i++) {
	    	result = ( result << 8 ) - Byte.MIN_VALUE + (int) bytes[i];
	    }
	    return result;
	}

	public static short toShort(byte[] bytes) {
		short result = 0;
	    for (int i=0; i<2; i++) {
	    	result = (short) (( result << 8 ) - Byte.MIN_VALUE + (short) bytes[i]);
	    }
	    return result;
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
		byte[] exponent = privateKey.getPrivateExponent().toByteArray();
		System.out.println(exponent.length);
		byte[] key = Arrays.copyOf(privateKey.getModulus().toByteArray(),128+exponent.length);
		for(int i=0; i<exponent.length; i++) {
			key[128+i] = exponent[i];
		}
		return key;
	}
}
  