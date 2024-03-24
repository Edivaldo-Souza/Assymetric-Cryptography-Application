package client;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Scanner;

import cript.ImplHmac;
import cript.ImplRsa;
import kdc.Distribuidor;
import mode.MessageWithKey;
import server.Banco;

public class Attacker {
	Banco banco;
	
	private static Scanner s = new Scanner(System.in);
	private static String hashKey = "";
	
	public static void main(String[] args) {
		boolean run = true;
		String msg, toMainMenu;
		
		while(run) {
			msg = menuInicial();

			if(msg.equals("fim")) {
				break;
			}
			toMainMenu = login(msg);
			System.out.println(toMainMenu);
			if(toMainMenu.equals("ok") || toMainMenu.equals("Usuario Invalido")) {
				System.out.println("Login com Sucesso!");
				menuPrincipal();
			}
			else System.out.println(toMainMenu);

		}
		System.out.println("Fim do programa");
		
		
	}
	
	public static String menuInicial() {
		
		String option, temp, fullMsg = "";
		
		System.out.println("Como deseja prosseguir:\n"
				+ "1 - Fazer Login\n"
				+ "2 - Criar Conta\n"
				+ "3 - Encerrar Programa\n"
				+ "Digite uma opcao: ");

		option = s.nextLine();
		s.nextLine();
		
		while(!option.equals("1") && !option.equals("2") && !option.equals("3")) {
			System.out.println("Opção Invalida! Tente novamente:\n"
					+ "1 - Fazer Login\n"
					+ "2 - Criar Conta\n"
					+ "3 - Encerrar Programa\n"
					+ "Digite uma opcao: ");

			option = s.nextLine();
			s.nextLine();
		}
		
		if(option.trim().equals("1")) {
			
			fullMsg = "1";
			
			System.out.println("Informe o numero da conta: ");
			temp = s.nextLine();
			s.nextLine();
			
			fullMsg += "_"+temp;
			System.out.println("Informe a senha: ");
			temp = s.nextLine();
			s.nextLine();
			
			fullMsg += "_"+temp;
			return fullMsg;
			
		}
		else if(option.trim().equals("2")) {
			
			String [] atributos = {"nome","CPF","endereco","numero de celular","senha"};
			
			fullMsg = "2";
			for(int i = 0; i<atributos.length; i++) {
				System.out.println("Informe seu "+atributos[i]+": ");
				temp = s.nextLine();
				s.nextLine();
				
				fullMsg += "_"+temp;
			}
			
			return fullMsg;
			
		}
		else if(option.trim().equals("3")) {
			return "fim";
		}
		return null;
	}
	
	private static String login(String dados) {
		if(dados.toCharArray()[0]=='1') {
			if(Banco.login(dados).equals("auth")) {
				Attacker.hashKey = Distribuidor.HASHKEY;
				return "ok";
			}
			return "Usuario Invalido";
		}
		else {
			return enviarDados(dados);
		}
		
	}

	private static String enviarDados(String dados) {
		String hash;
		try {
			if(dados.toCharArray()[0]=='2') {
				hash = ImplHmac.Hmac(Distribuidor.HASHKEY, dados);
			}
			else{
				if(Attacker.hashKey.isEmpty()) {
					return "Chave do Hash nao esta presente";
				}
				hash = ImplHmac.Hmac(Attacker.hashKey, dados);
			}
			
			String encryptedMsg = Distribuidor.aes.encrypt(dados);
			
			String encryptedReply = Banco.receberDados(encryptedMsg,hash);
			
			String finalReply = receberDados(encryptedReply.split("_")[0],encryptedReply.split("_")[1]);
			
			return finalReply;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return "Não foi possível estabelecer conexão";
	}
	
	public static String receberDados(String encodedMsg, String hash) {
		
		String decryptedMsg = Distribuidor.aes.decrypt(encodedMsg);
		
			String newHash;
			try {
				newHash = ImplHmac.Hmac(Distribuidor.HASHKEY, decryptedMsg);
				if(newHash.equals(hash)) {
					return decryptedMsg;
				}
				else
					return "Não foi possível estabelecer conexão";
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		return null;
	}
	
	private static void menuPrincipal() {
		
		String option, msg;
		int num;
		boolean keepRunning = true;
		
		while(keepRunning) {
			System.out.println("Ações disponíveis para conta:\n"
					+ "1 - Realizar Saque\n"
					+ "2 - Realizar Depósito\n"
					+ "3 - Realizar Transferência\n"
					+ "4 - Consultar Saldo\n"
					+ "5 - Consultar Envistementos\n"
					+ "6 - Sair\n"
					+ "Digite uma opcao: ");
			option = s.nextLine();
			s.nextLine();
			num = Integer.parseInt(option);
			
			switch(num) {
			case 1:
				System.out.println("Informe o valor do saque: ");
				option = s.nextLine();
				s.nextLine();
				
				msg = "s_"+option;
				
				System.out.println(enviarDados(msg));
				break;
				
			case 2:
				System.out.println("Informe o valor do depósito: ");
				option = s.nextLine();
				s.nextLine();
				
				msg = "d_"+option;
				System.out.println(enviarDados(msg));
				break;
				
			case 3:
				System.out.println("Informe o numero da conta para transferencia: ");
				option = s.nextLine();
				s.nextLine();
				
				System.out.println("Informe o valor da transferencia: ");
				msg = s.nextLine();
				s.nextLine();
				System.out.println(enviarDados("t_"+option+"_"+msg));
				break;
				
			case 4:
				msg = "c_";
				System.out.println(enviarDados(msg));
				break;
			case 5:
				System.out.println("Qual previsão deseja consultar:\n"
						+ "1 - Poupança\n"
						+ "2 - Renda Fixa\n"
						+ "Digite:");
				option = s.nextLine();
				s.nextLine();
				
				System.out.println("Informe o valor do investimento: ");
				msg = s.nextLine();
				s.nextLine();
				
				System.out.println(enviarDados("i_"+option+"_"+msg));
				break;
			case 6:
				System.out.println(enviarDados("sair"));
				keepRunning = false;
				Attacker.hashKey = "";
				break;
			}
				
		}
	}
}
