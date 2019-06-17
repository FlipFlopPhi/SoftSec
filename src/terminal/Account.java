package terminal;

import java.io.Serializable;

public class Account implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1200147919157742650L;

	static final Account testAccount = new Account();

	private int credit = 300;

	public Account() {
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
