//Fixed XOR
//Write a function that takes two equal-length buffers and produces their XOR combination.
//If your function works properly, then when you feed it the string:
//1c0111001f010100061a024b53535009181c
//... after hex decoding, and when XOR'd against:
//686974207468652062756c6c277320657965
//... should produce:
//746865206b696420646f6e277420706c6179

import java.math.BigInteger;
import java.util.Scanner;
public class question2 {
	
	/*Xors two BigInteger type numbers*/
	public BigInteger xor(BigInteger num1 , BigInteger num2) {
		BigInteger final_number = new BigInteger("0");
		final_number = num1.xor(num2);
		return final_number;
	}
	
	/*Converts decimal to binary format*/
	public String decimalTobinary(BigInteger decimal) {
		String binary = "";
		long buffer =0;
		BigInteger i = new BigInteger("0");
		BigInteger remainder = new BigInteger("0");
		while(decimal.compareTo(new BigInteger("0"))==1) {
			remainder = decimal.mod(new BigInteger("2"));
			binary = remainder+binary;
			decimal = decimal.divide(new BigInteger("2"));
		}		
		/*Checking for pair of 8, if not appends zero to the front*/
		while(binary.length()%8!=0) {			
			binary = 0+binary;
			}	
		return binary;
	}
	
	/*Converts hex to decimal*/
	public BigInteger hextoDecimal(String hex) {
		String s = "0123456789ABCDEF";
		int  j= hex.length()-1;
		int index =0;
		BigInteger power = new BigInteger("16");
		BigInteger number_buff = new BigInteger("0");
		BigInteger number = new BigInteger("0");
		hex =hex.toUpperCase();
		char buffer;
		for(long i=0;i<hex.length();i++) {
			buffer = hex.charAt((int) i);
			index = s.indexOf(buffer);
			number_buff=power.pow(j--);
			number_buff = number_buff.multiply(new BigInteger(""+index));
			number = number.add(number_buff);  
		}
		return number;
	}
	
	/*Converts binary string to hex*/
	public String binarytoHex(String  binary) {
		if (binary.length()%8!=0)
			return null;
		String buffer= "" ;
		String hex = "";
		for (int i=0;i+8<=binary.length();i +=8) {
			buffer = binary.substring(i,i+8);//8 Bits make one Byte
			int decimal = Integer.parseInt(buffer, 2);	//Converts byte to decimal
			buffer = Integer.toString(decimal,16); //Decimal to hex
			hex = hex +buffer;
		}
		return hex;
	}
	
	public void user_interface() {
		String hex1;
		String hex2;
		String binary;
		BigInteger result = new BigInteger("0");
		System.out.println("Enter the hext string 1");
		Scanner scan = new Scanner(System.in);
		hex1 = scan.nextLine();
		System.out.println("Enter the hex string 2");
		hex2 = scan.nextLine();
		if(hex2.length()!=hex1.length())
		{
			System.out.println("Error");
			return;
		}
		result = xor(hextoDecimal(hex1),hextoDecimal(hex2));
		binary = decimalTobinary(result);
		String hex = binarytoHex(binary);
		System.out.println("The xor'ed hex string is");
		System.out.println(hex);
		return;
	}
	
	public static void main(String args[]) {
		question2 m = new question2();
		m.user_interface();
	}
}
