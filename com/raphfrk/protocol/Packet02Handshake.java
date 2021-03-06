/*******************************************************************************
 * Copyright (C) 2012 Raphfrk
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/
package com.raphfrk.protocol;

public class Packet02Handshake extends Packet{

	public Packet02Handshake(Packet packet) {
		super(packet, 2);
	}
	
	public Packet02Handshake(String username, String serverhost, int port) {
		super(1 + 1 + 2 +username.length()*2 + 2 + serverhost.length()*2 + 4, (byte)2);
		super.writeByte((byte)0x2);
		//Protocol version
		super.writeByte((byte) 39);
		super.writeString16(username);
		super.writeString16(serverhost);
		super.writeInt(port);
	}
	
	public byte getProtocolVersion(){
		return getByte(1);
	}
	
	public String getUsername() {
		return getString16(2);
	}
	
	public String getServerHost() {
		short length1=(short)(getShort(2)*2);
		return getString16(length1+2+2);
	}
	
	public int getPort(){
		short length1=(short)(getShort(2)*2);
		short length2=(short)(getShort(length1+2)*2);
		return getInt(length2+2);
	}
}