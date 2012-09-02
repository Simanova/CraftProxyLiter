package com.raphfrk.protocol;

public class PacketCDClientStatus extends Packet
{
	
	public PacketCDClientStatus(Packet packet) {
		super(packet, 0xCD);
	}
	
	public PacketCDClientStatus(byte status){
		super(2, (byte)0xCD);
		super.writeByte((byte) 0xCD);
		super.writeByte(status);
	}
}