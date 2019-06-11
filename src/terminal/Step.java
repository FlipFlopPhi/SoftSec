package terminal;

public enum Step {
	Handshake1((short)1)
	,Handshake2((short)2)
	,Handshake3((short)3)
	,Handshake4((short)4)
	,Pin((short)5)
	,Charge((short)6)
	,Pump1((short)7)
	,Personalize((short)8)
	,Personalize2((short)9)
	,Personalize3((short)10)
	, Personalize4((short)8);
	
	
	public final byte P1;
	public final byte P2;
	
	Step(short flags) {
		this.P2 = (byte) flags;
		this.P1 = (byte) (flags >> 8);
	}
}
