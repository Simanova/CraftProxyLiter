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
package com.raphfrk.craftproxyliter;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import com.raphfrk.craftproxyliter.Globals;
import com.raphfrk.craftproxyliter.LocalhostIPFactory;
import com.raphfrk.protocol.ProtocolInputStream;
import com.raphfrk.protocol.ProtocolOutputStream;

public class LocalSocket {

	public boolean success;

	private DataInputStream in;
	public ProtocolInputStream pin;
	private DataOutputStream out;
	public ProtocolOutputStream pout;
	public final Socket socket;
	public final PassthroughConnection ptc;
	public final int worldHeight;
	
	public static Socket openSocket(String hostname, int port, PassthroughConnection ptc) {

		ptc.printLogMessage("Attempting to connect to: " + hostname + ":" + port);

		Socket socket = null;

		try {
			if(Globals.varyLocalhost() && (hostname.trim().equals("localhost") || isLocalIP(hostname.trim()))) {
				String fakeLocalIP = LocalhostIPFactory.getNextIP();
				if(!Globals.isQuiet()) {
					ptc.printLogMessage("Connecting to: " + hostname + ":" + port + " from " + fakeLocalIP );
				}
				socket = new Socket(hostname, port, InetAddress.getByName(fakeLocalIP), 0);
			} else {
				socket = new Socket(hostname, port);
			}			
		} catch (UnknownHostException e) {
			ptc.printLogMessage("Unknown hostname: " + hostname);
			return null;
		} catch (IOException e) {
			ptc.printLogMessage(e.getMessage());
			if(hostname.trim().startsWith("localhost")) {
				ptc.printLogMessage("Trying alternative IPs on localhost, this is slow");
				List<String> hostnames = getLocalIPs();
				for(String h : hostnames) {
					ptc.printLogMessage("Attempting to connect to: " + h + ":" + port);
					try {
						socket = new Socket(h, port);
					} catch (IOException ioe) {
						continue;
					}
					ptc.printLogMessage("WARNING: Used alternative IP to connect: " + h);
					ptc.printLogMessage("You should change your default server parameter to include the IP address: " + h);
					break;
				}
			}
			if(socket == null) {
				ptc.printLogMessage("Unable to open socket to " + hostname + ":" + port);
				return null;
			}
		}
		try {
			socket.setSoTimeout(Globals.getSOTimeout());
		} catch (SocketException e) {
			ptc.printLogMessage("Unable to set socket timeout");
			if(socket != null) {
				try {
					socket.close();
				} catch (IOException ioe){
					return null;
				}
			}
			return null;
		}

		return socket;

	}

	public static boolean isLocalIP(String hostname) {
		return getLocalIPs().contains(hostname);
	}

	public static List<String> getLocalIPs() {

		Enumeration<NetworkInterface> interfaces;

		try {
			interfaces = NetworkInterface.getNetworkInterfaces();
		} catch (SocketException e) {
			return null;
		}

		List<String> ips = new ArrayList<String>();

		while(interfaces.hasMoreElements()) {
			NetworkInterface current = interfaces.nextElement();

			if(current != null) {
				Enumeration<InetAddress> addresses = current.getInetAddresses();

				while(addresses.hasMoreElements()) {
					InetAddress addr = addresses.nextElement();
					if(addr != null) {
						ips.add(addr.getHostAddress());
					}
				}
			}
		}

		return ips;

	}

	public boolean closeSocket(PassthroughConnection ptc) {

		try {
			pout.flush();
			pout.close();
			pin.close();
			in.close();
			socket.close();
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	LocalSocket(Socket socket, PassthroughConnection ptc, int worldHeight) {
		this.ptc = ptc;
		this.socket = socket;
		this.worldHeight=worldHeight;
		DataInputStream inLocal = null;
		DataOutputStream outLocal = null;
		try {
			inLocal = new DataInputStream( this.socket.getInputStream() );
		} catch (IOException e) {
			ptc.printLogMessage("Unable to open data stream to client");
			if( inLocal != null ) {
				try {
					inLocal.close();
					socket.close();
				} catch (IOException e1) {
					ptc.printLogMessage("Unable to close data stream to client");
				}
			}
			in = null;
			pin = null;
			out = null;
			pout = null;
			success = false;
			return;
		}

		try {
			outLocal = new DataOutputStream( this.socket.getOutputStream() );
		} catch (IOException e) {
			ptc.printLogMessage("Unable to open data stream from client");
			if( outLocal != null ) {
				try {
					outLocal.close();
					socket.close();
				} catch (IOException e1) {
					ptc.printLogMessage("Unable to close data stream from client");
				}
			}
			in = null;
			pin = null;
			out = null;
			pout = null;
			success = false;
			return;
		}
		in = inLocal;
		pin = new ProtocolInputStream(in, 255*16*1024);
		out = outLocal;
		pout = new ProtocolOutputStream(out);
		success = true;
	}
	
	public void setAES() {
		BufferedBlockCipher in = new BufferedBlockCipher(new CFBBlockCipher(new AESFastEngine(), 8));
		in.init(false, new ParametersWithIV(new KeyParameter(this.ptc.getSecretKey().getEncoded()), this.ptc.getSecretKey().getEncoded(), 0, 16));
		BufferedBlockCipher out = new BufferedBlockCipher(new CFBBlockCipher(new AESFastEngine(), 8));
		out.init(true, new ParametersWithIV(new KeyParameter(this.ptc.getSecretKey().getEncoded()), this.ptc.getSecretKey().getEncoded(), 0, 16));
		this.in = new DataInputStream(new CipherInputStream(this.in, in));
		this.out = new DataOutputStream(new CipherOutputStream(this.out, out));
		pin = new ProtocolInputStream(this.in, 255*16*1024);
		pout = new ProtocolOutputStream(this.out);
	}

}