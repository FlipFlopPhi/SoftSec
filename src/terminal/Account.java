package terminal;

public class Account {

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
