package cript;

import java.util.Base64;

public class ImplCifraDeVernam {
	public static String encrypt(String msg,String key) {
		StringBuilder sb = new StringBuilder();
		
		for(int i = 0; i<msg.length(); i++) {
			
			char character = msg.charAt(i);
			char keyChar = key.charAt(i%key.length());
			char encryptedChar = (char)(character^keyChar);
			
			sb.append(encryptedChar);
		}
		
		return sb.toString();
	}
	
	public static String decrypt(String msg, String key) {
		return encrypt(msg,key);
	}
}
