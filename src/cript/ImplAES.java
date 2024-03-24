package cript;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class ImplAES {
	private KeyGenerator keyGenerator;
	public SecretKey key;
	private String msg;
	private String msgCrypted;
	
	public ImplAES() {
		keyGen();
	}
	
	private void keyGen() {
		try {
			keyGenerator = KeyGenerator.getInstance("AES");
			key = keyGenerator.generateKey();
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public String encrypt(String text) {
		byte[] bytesEncryptedMsg;
		Cipher cipher;
		msg = text;
		
		try {
			cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, this.key);
			
			bytesEncryptedMsg = cipher.doFinal(msg.getBytes());
			msgCrypted = Base64.getEncoder().encodeToString(bytesEncryptedMsg);
			

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return msgCrypted;
	}
	
	public String decrypt(String encryptedText) {
		byte[] bytesEncprytedMsg = Base64.getDecoder().decode(encryptedText);
		
		Cipher decipher;
		
		try {
			decipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			decipher.init(Cipher.DECRYPT_MODE,key);
			
			byte[] bytesDecryptedMsg = decipher.doFinal(bytesEncprytedMsg);
			String decryptedMsg = new String(bytesDecryptedMsg);
			
			msg = decryptedMsg;
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return msg;
	}
}
