import java.util.Scanner;
import java.math.*;
public class question1 {
	
	/*Converts 8 pair to 6 pair. Appends zeros at the end if needed*/
	public void eightTosix(String binary) {
		String newBinary = binary;
		
		if(newBinary.length()%6!=0) {
			newBinary = newBinary+0;
		}		
		binarytoDecimal(newBinary);
		return;
	}
	
	/*Binary to Base64 Conversion*/
	public void binarytoDecimal(String binary) {
		String s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";//Base64 table
		StringBuffer buffer1 = new StringBuffer();
		String result ="";
		String buffer=null;
		int number =0;
		for(int i=0;i+6<=binary.length();i +=6) {
			buffer = binary.substring(i,i+6);
			number = Integer.parseInt(buffer, 2);
			buffer1.append(s.charAt(number));		
		}
		result = buffer1.toString();
		System.out.println("base64 = ");
		System.out.println(result);
		return ;
	}
	
	/*Decimal to binary*/
	public String decimalTobinary(BigInteger decimal) {
		String binary = "";
		long buffer =0;
		BigInteger i = new BigInteger("0");
		BigInteger remainder = new BigInteger("0");
		while(decimal.compareTo(new BigInteger("0"))==1) {
			remainder = decimal.mod(new BigInteger("2"));
			binary = remainder+binary;
		//	System.out.println("Here");
			decimal = decimal.divide(new BigInteger("2"));
		}
		
		/*Checking for pair of 8, if not appends zero to the front*/
		while(binary.length()%8!=0) {			
			binary = 0+binary;
			}	
		return binary;
	}
	/*Converts hex to decimal*/
	public BigInteger hexToDecimal(String hex)
	{
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
	
	public void user_interface() {
		String hex=null;
		BigInteger decimal = new BigInteger("0");
		String binary;
		Scanner scan1 = new Scanner(System.in);
		System.out.println("Please enter the hex string");
		hex = scan1.nextLine();
		decimal =hexToDecimal(hex);// Hex to Decimal
		binary = decimalTobinary(decimal);//Decimal to Binary
		eightTosix(binary);//For Base64 conversion
		return;
	}
	
	public static void  main(String args[]) {
		question1 m = new question1();
		m.user_interface();
	}
}
