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

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import com.raphfrk.protocol.EncryptionUtil;
import com.raphfrk.protocol.Packet;
import com.raphfrk.protocol.Packet01Login;
import com.raphfrk.protocol.Packet02Handshake;
import com.raphfrk.protocol.PacketFCKeyResponse;
import com.raphfrk.protocol.PacketFDKeyRequest;
import com.raphfrk.protocol.PacketFFKick;

public class LoginManager {
	
	private static long MAGIC_SEED = 0x0123456789ABCDEFL;

	public static String getUsername(LocalSocket clientSocket, ConnectionInfo info, PassthroughConnection ptc, String pingHostname, Integer pingPort) {
		Packet packet = new Packet();

		try {
			packet = clientSocket.pin.getPacket(packet);
			if(packet == null) {
				return "Client didn't send handshake packet";
			}
		} catch (EOFException eof) {
			return "Client closed connection before sending handshake";
		} catch (IOException ioe) {
			return "IO Error reading client handshake";
		}

		if(packet.getByte(0) == 0x02) {
			Packet02Handshake CtSHandshake = new Packet02Handshake(packet);
			info.setUsername(CtSHandshake.getUsername());
			info.setUsernameRaw(CtSHandshake.getUsername());
			info.clientVersion=CtSHandshake.getProtocolVersion();
		} else if (packet.getByte(0) == 0x52){
			Packet52ProxyLogin proxyLogin = new Packet52ProxyLogin(packet);
			info.setUsername(proxyLogin.getUsernameSplit());
			info.setUsernameRaw(proxyLogin.getUsername());
			info.setHostname(proxyLogin.getHostname());
			info.forwardConnection = true;
			ptc.printLogMessage("Proxy to proxy connection received, forwarding to " + ptc.connectionInfo.getHostname());
		} else if ((packet.getByte(0) & 0xFF) == 0xFE) {
			long currentTime = System.currentTimeMillis();
			String address = ptc.IPAddress;
			Long lastPing = ptc.proxyListener.lastPing.get(address);
			ptc.proxyListener.lastPing.put(address, currentTime);
			//if (lastPing == null || lastPing + 5000 < currentTime) {
				Long oldLastLogin = ptc.proxyListener.lastLoginOld.get(address);
				if (oldLastLogin == null) {
					ptc.proxyListener.lastLogin.remove(address);
				} else {
					ptc.proxyListener.lastLogin.put(address, oldLastLogin);
				}
			//}
			if (pingPort == null || pingHostname == null) {
				return "Server offline";
			} else {
				ptc.printLogMessage("Forwarding ping");
				Socket serverSocket;
				try {
					serverSocket = new Socket(pingHostname, pingPort);
				} catch (IOException ioe) {
					return "Unable to connect";
				}
				LocalSocket serverLocalSocket;
				try {
					serverSocket.setSoTimeout(1000);
					serverLocalSocket = new LocalSocket(serverSocket, ptc, Globals.getMaxWorldHeight());
				} catch (IOException ioe) {
					return "Unable to connect";
				}
				try {
					serverLocalSocket.pout.sendPacket(packet);
				} catch (IOException e) {
					serverLocalSocket.closeSocket(ptc);
					return "Send ping failure";
				}
				Packet recv = new Packet();
				try {
					recv = serverLocalSocket.pin.getPacket(recv);
				} catch (IOException e) {
					serverLocalSocket.closeSocket(ptc);
					return "Receive ping failure";
				}
				serverLocalSocket.closeSocket(ptc);
				if ((recv.getByte(0) & 0xFF) == 0xFF) {
					PacketFFKick kick = new PacketFFKick(recv);
					return kick.getString16(1);
				} else {
					return "Bad ping kick packet";
				}
				
			}
		} else {
			return "Unknown login packet id " + packet.getByte(0);
		}

		return null;

	}

	public static String bridgeLogin(LocalSocket clientSocket, LocalSocket serverSocket, ConnectionInfo info, PassthroughConnection ptc, boolean reconnect, String fullHostname) {

		Packet packet = new Packet();

		Packet CtSHandshake;
		
		String password = Globals.getPassword();
		
		if(fullHostname == null || password == null) {
			if(fullHostname != null) {
				ptc.printLogMessage("WARNING: attempting to log into another proxy which has authentication enabled but password has not been set");
			}
			ptc.printLogMessage("Connecting using proxy to server connection format");
			CtSHandshake = new Packet02Handshake(info.getUsername(), info.getHostname(), info.getPort());
		} else {
			ptc.printLogMessage("Connecting using proxy to proxy connection format");
			CtSHandshake = new Packet52ProxyLogin("", fullHostname, info.getUsernameRaw());
		}

		try {
			if(serverSocket.pout.sendPacket(CtSHandshake) == null) {
				return "Server didn't accept handshake packet";
			}
		} catch (EOFException eof) {
			return "Server closed connection before accepting handshake";
		} catch (IOException ioe) {
			return "IO Error sending client handshake to server";
		}
		System.out.println("Handshake forwarded to server");
		
		try {
			packet = serverSocket.pin.getPacket(packet);
			if(packet == null) {
				return "Server didn't send handshake packet";
			}
		} catch (EOFException eof) {
			return "Server closed connection before sending handshake";
		} catch (IOException ioe) {
			return "IO Error reading server handshake";
		}
		
		//First connection, do encryption and session checking and such
		if(!reconnect) {

			//System.out.println("Generating FD Key Request packet");
			PublicKey key = ptc.proxyListener.getKeys().getPublic();
			ptc.setLoginKey(Long.toString(EncryptionUtil.random().nextLong(), 16));
            byte token[] = new byte[4];
            EncryptionUtil.random().nextBytes(token);
            ptc.setToken(token);
            
            PacketFDKeyRequest keyrequest=new PacketFDKeyRequest(ptc.getLoginKey(), key.getEncoded(), token);
			//System.out.println("Sending FD Key Request packet");
			try {
				if(clientSocket.pout.sendPacket(keyrequest) == null) {
					return "Client didn't accept key request packet";
				}
			} catch (EOFException eof) {
				return "Client closed connection before accepting key request packet";
			} catch (IOException ioe) {
				return "IO Error sending server login";
			}
			//System.out.println("Done");
			
			//System.out.println("Recieving key response packet");
			Packet keyresponsepacket=null;
			try {
				keyresponsepacket=clientSocket.pin.getPacket(keyresponsepacket);
			} catch (EOFException eof) {
				return "Client closed connection before sending key response packet";
			} catch (IOException ioe) {
				return "IO Error receiving client key response packet";
			}
			
			if(keyresponsepacket == null) {
				return "Client didn't send key response packet";
			}

			//System.out.println("Receieved");
			//System.out.println("Parsing key response packet");
			PacketFCKeyResponse keyresponse=new PacketFCKeyResponse(keyresponsepacket);
			//System.out.println("Packet ID:"+(keyresponse.buffer[keyresponsepacket.start] & 0xFF));
			keyresponse.initData();
			//System.out.println("Data initialized");
	        PrivateKey priv = ptc.proxyListener.getKeys().getPrivate();

			//System.out.println("Setting secret key");
	        ptc.setSecretKey(new SecretKeySpec(encryptBytes(priv, keyresponse.sharedKey), "AES/CBC/PKCS5Padding"));
			
	        //System.out.println("Checking token reply");
	        if (!Arrays.equals(ptc.getToken(), encryptBytes(priv, keyresponse.verifyToken))) {
	            return "Invalid client token reply";
	        }
			
	        System.out.println("Authing with session.minecraft.net");
			String encrypted = new BigInteger(EncryptionUtil.encrypt(ptc.getLoginKey(), ptc.proxyListener.getKeys().getPublic(), ptc.getSecretKey())).toString(16);
			String response = null;
			
			try {
	            URL url = new URL("http://session.minecraft.net/game/checkserver.jsp?user=" + URLEncoder.encode(info.getUsername(), "UTF-8") + "&serverId=" + URLEncoder.encode(encrypted, "UTF-8"));
	            BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
	            response = reader.readLine();
	            reader.close();
	        } catch (IOException e) {
	            response = e.toString();
	            return response;
	        }
			
			if(!response.equals("YES")) {
				return "Failed to verify username!";
			}
	        
			//Send empty key response packet to trigger client encryption
	        packet = new Packet(5);
			packet.writeByte((byte)0xFC);
			packet.writeShort((short)0);
			packet.writeShort((short)0);
			try {
				if(clientSocket.pout.sendPacket(packet) == null) {
					return "Client didn't accept init encryption (empty key request) packet";
				}
			} catch (EOFException eof) {
				return "Client closed connection before accepting init encryption (empty key request)";
			} catch (IOException ioe) {
				return "IO Error sending init encryption (empty key request)";
			}
			
			System.out.println("Switching to encrypted stream on client socket");
			clientSocket.setAES();
			
			packet = null;
			try {
				if(clientSocket.pin.getPacket(packet) == null) {
					return "Client didn't send client status packet";
				}
			} catch (EOFException eof) {
				return "Client closed connection before sending client status packet";
			} catch (IOException ioe) {
				return "IO Error receiving client status packet";
			}
			
		//Else, not our first session. Get stuff set up with the server.
		} else {
			System.out.println("Reconnecting");
			String username = info.getUsername();
			packet = new Packet(200);
			packet.writeByte((byte)0x01);
			packet.writeInt(info.clientVersion);
			packet.writeString16(username.substring(0,Math.min(128, username.length())));
			packet.writeLong(0);
			packet.writeString16("");
			packet.writeInt(0);
			packet.writeByte((byte)0);
			packet.writeByte((byte)0);
			packet.writeByte((byte)0);
			packet.writeByte((byte)0);	
		}

		Packet CtSLogin = new Packet(2);
		CtSLogin.writeByte((byte) 0xCD);
		CtSLogin.writeByte((byte)0);
		try {
			if(serverSocket.pout.sendPacket(CtSLogin) == null) {
				return "Server didn't accept login packet";
			}
		} catch (EOFException eof) {
			return "Server closed connection before accepting login";
		} catch (IOException ioe) {
			return "IO Error sending client login to server";
		}
		//System.out.println("Sent client status packet to server");
		
		try {
			packet = serverSocket.pin.getPacket(packet);
			if(packet == null) {
				return "Server didn't send login packet";
			}
		} catch (EOFException eof) {
			return "Server closed connection before sending login";
		} catch (IOException ioe) {
			return "IO Error reading server login";
		}

		Packet01Login StCLogin = new Packet01Login(packet);	

		info.serverPlayerId = StCLogin.getUserEntityId();
		info.loginDifficulty = StCLogin.getDifficulty();
		info.loginDimension = StCLogin.getDimension();
		info.loginUnknownRespawn = StCLogin.getUnknown();
		info.loginCreative = StCLogin.getMode();
		info.levelType = StCLogin.getLevelType();
		//System.out.println(info.serverPlayerId+":"+info.loginDimension+":"+info.loginUnknownRespawn+":"+info.loginCreative+":"+info.levelType+":"+StCLogin.getMaxPlayers());
		if(!reconnect) {
			info.clientPlayerId = StCLogin.getUserEntityId();
			try {
				if(clientSocket.pout.sendPacket(StCLogin) == null) {
					return "Client didn't accept login packet";
				}
			} catch (EOFException eof) {
				return "Client closed connection before accepting login";
			} catch (IOException ioe) {
				return "IO Error sending server login";
			}
		}

		Packet keepalive = new Packet(5);
		keepalive.writeByte((byte) 0x00);
		keepalive.writeByte((byte)0);
		keepalive.writeByte((byte)0);
		keepalive.writeByte((byte)0);
		keepalive.writeByte((byte)0);
		try {
			if(serverSocket.pout.sendPacket(keepalive) == null) {
				return "Server didn't accept keepalive packet";
			}
		} catch (EOFException eof) {
			return "Server closed connection before accepting keepalive";
		} catch (IOException ioe) {
			return "IO Error sending client keepalive to server";
		}
		
		return null;

	}

	private static byte[] encryptBytes(PrivateKey key, byte[] bytes) {
		try {
			Cipher cipher = Cipher.getInstance(key.getAlgorithm());
			cipher.init(2, key);
			return cipher.doFinal(bytes);
		} catch (InvalidKeyException e) {
			System.out.println("InvalidKeyException: "+e.getMessage());
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("NoSuchAlgorithmException: "+e.getMessage());
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			System.out.println("NoSuchPaddingException: "+e.getMessage());
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			System.out.println("IllegalBlockSizeException: "+e.getMessage());
			e.printStackTrace();
		} catch (BadPaddingException e) {
			System.out.println("BadPaddingException: "+e.getMessage());
			e.printStackTrace();
		}

		return null;
	}
}
