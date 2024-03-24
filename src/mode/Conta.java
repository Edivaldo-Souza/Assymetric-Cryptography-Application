package mode;

public class Conta {
	private String accoutNumber;
	private String password;
	private String userName;
	private String CPF;
	private String address;
	private String phoneNumber;
	private double saldo = 0.0;
	
	
	
	public Conta(String accoutNumber, String password, String userName, String cPF, String address, String phoneNumber) {
	
		this.accoutNumber = accoutNumber;
		this.password = password;
		this.userName = userName;
		CPF = cPF;
		this.address = address;
		this.phoneNumber = phoneNumber;
	}
	
	
	public String getAccoutNumber() {
		return accoutNumber;
	}
	public void setAccoutNumber(String accoutNumber) {
		this.accoutNumber = accoutNumber;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getUserName() {
		return userName;
	}
	public void setUserName(String userName) {
		this.userName = userName;
	}
	public String getCPF() {
		return CPF;
	}
	public void setCPF(String cPF) {
		CPF = cPF;
	}
	public String getAddress() {
		return address;
	}
	public void setAddress(String address) {
		this.address = address;
	}
	public String getPhoneNumber() {
		return phoneNumber;
	}
	public void setPhoneNumber(String phoneNumber) {
		this.phoneNumber = phoneNumber;
	}
	public double getSaldo() {
		return saldo;
	}
	public void setSaldo(double saldo) {
		this.saldo = saldo;
	}
	
	public String toString() {
		String texto = "Numero da conta: "+this.accoutNumber+"\n"
				+ "Nome do cliente: "+this.userName+"\n"
				+ "CPF: "+this.CPF+"\n"
				+ "Endereço: "+this.address+"\n"
				+ "Numero de celular: "+this.phoneNumber+"\n";
		return texto;
	}
	
	
}
