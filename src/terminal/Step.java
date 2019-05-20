package terminal;

public enum Step {
	Handshake1((short)1)
	,Handshake2((short)2)
	,Pin((short)3)
	,Charge((short)4)
	,Pump1((short)5)
	,Pump2((short)6)
	,Personalize((short)7)
	,Personalize2((short)8)
	,Personalize3((short)9);
	
	
	public final byte P1;
	public final byte P2;
	
	Step(short flags) {
		this.P2 = (byte) flags;
		this.P1 = (byte) (flags >> 8);
	}
}
