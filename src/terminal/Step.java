package terminal;

public enum Step {
	Handshake1((short)1)
	,Handshake2((short)2)
	,Handshake3((short)3)
	,Handshake4((short)4)
	,Handshake5((short)5)
	,Pin((short)12)
	,Charge((short)6)
	,Pump1((short)7)
	,Personalize((short)8)
	,Personalize2((short)9)
	,Personalize3((short)10)
	, Personalize4((short)11);
	
	
	public final byte P1;
	public final byte P2;
	
	Step(short flags) {
		this.P2 = (byte) flags;
		this.P1 = (byte) (flags >> 8);
	}
}
