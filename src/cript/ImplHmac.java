package cript;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class ImplHmac {
	public static final String ALG = "HmacSHA256";
	
	public static String Hmac(String key, String msg) throws Exception{
		
		Mac shaHmac = Mac.getInstance(ALG);
		
		SecretKeySpec macKey = new SecretKeySpec(key.getBytes("UTF-8"),ALG);
		shaHmac.init(macKey);
		
		byte[] byteHmac = shaHmac.doFinal(msg.getBytes("UTF-8"));
		return byteToHex(byteHmac);
	}
	
	private static String byteToHex(byte[] bytes) {
		StringBuilder s = new StringBuilder();
		for(byte b : bytes) {
			s.append(String.format("%02x", b));
		}
		return s.toString();
	}
}
