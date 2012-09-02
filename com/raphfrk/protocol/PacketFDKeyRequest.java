package com.raphfrk.protocol;

public class PacketFDKeyRequest extends Packet
{
	/*
	 * Packet ID 	
		0xFD 	
		Field Name 	Field Type
		Server id 	string 		
		Public key length 	short 		
		Public key 	byte array 		
		Verify token length 	short 		
		Verify token 	byte array 		
		Total Size: 	7 bytes + length of string + length of key + length of token 
	 */
	public String serverId;
	public byte[] pubKey;
	public byte[] verifyToken;
	
	public PacketFDKeyRequest(Packet packet) {
		super(packet, 253);
	}
	
	public String getServerId(){
		return getString16(1);
	}

	public PacketFDKeyRequest(String paramServerId, byte[] paramPublicKey, byte[] paramVerifyToken) {
		super(1 + 2 +paramServerId.length()*2 + 2 + paramPublicKey.length + 2 + paramVerifyToken.length, (byte)0xFD);
		this.serverId = paramServerId;
		this.pubKey = paramPublicKey;
		this.verifyToken = paramVerifyToken;
		//2 + ServerId.length() * 2 + 2 + publickey.getEncoded().length + 2 + token.length
		super.writeByte((byte)0xFD);
		super.writeString16(serverId);
		super.writeShort((short) this.pubKey.length);
		for(byte abyte : this.pubKey){
			super.writeByte(abyte);
		}
		super.writeShort((short)this.verifyToken.length);
		for(byte abyte : this.verifyToken){
			super.writeByte(abyte);
		}
	}
}