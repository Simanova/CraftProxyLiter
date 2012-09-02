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

public class Packet01Login extends Packet {

	public Packet01Login(Packet packet) {
		super(packet, 1);
	}

	public int getUserEntityId() {
		return getInt(1);
	}

	private int getLevelStringStart() {
		return 5;
	}

	public String getLevelType() {
		return getString16(getLevelStringStart());
	}

	private int getModeStart() {
		return getLevelStringStart() + getString16Length(getLevelStringStart());
	}

	public byte getMode() {
		return getByte(getModeStart());
	}

	public byte getDimension() {
		return getByte(getModeStart() + 1);
	}

	public byte getDifficulty() {
		return getByte(getModeStart() + 2);
	}
	
	public byte getUnknown() {
		return getByte(getModeStart() + 3);
	}

	public byte getMaxPlayers() {
		return getByte(getModeStart() + 4);
	}

}