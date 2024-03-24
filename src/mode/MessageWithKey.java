package mode;

import java.security.PublicKey;

public class MessageWithKey {
	private String msg;
	private PublicKey key;
	
	public MessageWithKey(String msg, PublicKey key) {
		
		this.msg = msg;
		this.key = key;
	}

	public String getMsg() {
		return msg;
	}

	public void setMsg(String msg) {
		this.msg = msg;
	}

	public PublicKey getKey() {
		return key;
	}

	public void setKey(PublicKey key) {
		this.key = key;
	}
	
	
	
}
