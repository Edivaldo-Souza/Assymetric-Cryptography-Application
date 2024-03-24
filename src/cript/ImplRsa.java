package cript;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class ImplRsa {
	private BigInteger publicKey;
	private BigInteger privateKey;
	private BigInteger destPublicKey;
	private BigInteger n;
	
	public ImplRsa(){
		createKey();
	}
	
	private void createKey(){
		BigInteger p,q,e,phi;
		SecureRandom random = new SecureRandom();
		p = BigInteger.probablePrime(512, random);
		q = BigInteger.probablePrime(512, random);
		n = p.multiply(q);
		phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        
		e = BigInteger.TWO;
		while(phi.gcd(e).compareTo(BigInteger.ONE) != 0 && e.compareTo(phi)<0) {
			e = e.add(BigInteger.ONE);
		}
		
		publicKey = e;
		privateKey = publicKey.modInverse(phi);
	}
	
	public String encrypt(String msg){
		StringBuilder sb = new StringBuilder();
		BigInteger temp;
		for(int i = 0; i<msg.length(); i++) {
			temp = new BigInteger(Integer.toString(msg.charAt(i)));
			temp = temp.modPow(destPublicKey,n);
			
			sb.append(temp+",,,");
		}
		
		return sb.toString();
	}
	
	public String decrypt(String msg){
		StringBuilder sb = new StringBuilder();
		BigInteger temp;
		char letter;
		for(String str : msg.split(",,,")) {
			temp = new BigInteger(str);
			temp = temp.modPow(privateKey,n);
			letter = (char) temp.intValue();
			sb.append(letter);
		}
		
		return sb.toString();
	}
	
	public void setDestPublicKey(BigInteger key) {
		this.destPublicKey = key;
	}
	
	public BigInteger getPublicKey() {
		return this.publicKey;
	}
	

}
