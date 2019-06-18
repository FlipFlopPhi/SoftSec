package terminal;

import java.io.Serializable;
import java.math.BigInteger;

public class Account implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1200147919157742650L;

	private int credit = 300;
	public final String name;
	public final BigInteger bsn;

	public Account(String name, BigInteger bsn) {
		this.name = name;
		this.bsn = bsn;
	}

	public void decreaseBy(int amountRequested) {
		credit -= amountRequested;
	}

	public void increaseBy(int amountRequested) {
		credit += amountRequested;
	}

	public int getCreditStored() {
		return credit;
	}

}
