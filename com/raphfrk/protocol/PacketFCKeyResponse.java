package com.raphfrk.protocol;

public class PacketFCKeyResponse extends Packet
{
	
	public PacketFCKeyResponse(Packet packet) {
		super(packet, 252);
	}
	
	/*short size = getShort(buffer, position, mask);
	position = (position + 2);
	if(size<0){
		break;
	}
	if(size > maxPacketSize) {
		if(position - start <= dataLength) {
			System.err.println("Size to large in short sized byte array");
			System.out.println("Size to large in short sized byte array");
		}
		return null;
	}
	position = (position + size);
	if(size < 0) {
		return null;
	}
	break;*/
	
	public byte[] sharedKey;
	public byte[] verifyToken;
	
	public void initData(){
		//System.out.println("wakka wakka");
		int position=1;
		short sharedKeyLength=super.getShort(position);
		//System.out.println("Shared key length:"+sharedKeyLength);
		position = position + 2;
		byte sharedKey[] = new byte[sharedKeyLength];
		//StringBuffer hexString = new StringBuffer();
		//int numofbytes=0;
		for(int k=0;k<sharedKeyLength;k++){
			//numofbytes++;
		    //hexString.append(" "+Integer.toHexString(0xFF & this.buffer[this.start+k+position]));
			sharedKey[k]=this.buffer[this.start+k+position];
		}
		//System.out.println("Num of bytes:"+numofbytes);
		//System.out.println(hexString.toString());
		position = position + sharedKeyLength;
		
		short verifyTokenLength=super.getShort(position);
		//System.out.println("Token length:"+sharedKeyLength);
		position = position + 2;
		byte verifyToken[] = new byte[verifyTokenLength];
		for(int k=0;k<verifyTokenLength;k++){
			verifyToken[k]=this.buffer[this.start+k+position];
		}
		position = position + verifyTokenLength;
		//System.out.println(position+":"+(this.end-this.start));
		this.sharedKey = sharedKey;
		this.verifyToken = verifyToken;
	}
	
	public byte[] getSharedKey() {
		return this.sharedKey;
	}
	
	public byte[] getVerifyToken() {
		return this.verifyToken;
	}
	
}