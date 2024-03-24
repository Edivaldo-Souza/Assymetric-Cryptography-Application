package kdc;

import cript.ImplAES;
import cript.ImplHmac;
import cript.ImplRsa;

public class Distribuidor {
	public static final String VERNANKEY = "chave093824";
	public static final String HASHKEY = "chave893842";
	public static ImplRsa rsaUser = new ImplRsa();
	public static ImplRsa rsaBanco = new ImplRsa();
	public static ImplHmac hash = new ImplHmac();
	public static ImplAES aes = new ImplAES();
	
}
