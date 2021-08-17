package com.icici.encryption;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.web.bind.annotation.RestController;


@RestController
@SpringBootApplication
@ComponentScan(basePackages={"com.icici.encryption"})

public class EncryptionApplication {	
	
	public static String EncryptedData;
	public static String Encryptedkey;
	public static String randomNumberiv;
	public static String restserverupload;

	public static void main(String[] args) throws Exception {
		
		AES aes = new AES();
		
		
		SpringApplication.run(EncryptionApplication.class, args);
		
		String rest = aes.getProductList();
		
		
	 
		String strJSONMessage = rest;
	 
				
	//	System.out.println("strJSONMessage Data :" + strJSONMessage);

	//	System.out.println("aesserverupload :" + aesserverupload);
		
		String randomNumber = aes.generateRandom(16);
		String randomNumberTwo = aes.generateRandomTwo(16);

	//	System.out.println("randomNumberTwo :" + randomNumberTwo);

		 randomNumberiv = aes.generateRandom(16);
		String randomNumberkey = aes.generateRandom(16);

		String dataconcate = randomNumberTwo + strJSONMessage;
	//	System.out.println("dataconcate :" + dataconcate);

	   Encryptedkey = aes.getRequestkey(randomNumber);
		
		System.out.println("Encryptedkeys :" + Encryptedkey);
		
		
		
		String keyss ="";
		
		EncryptedData = aes.getRequestData(randomNumberkey,randomNumberiv, dataconcate);

		System.out.println("EncryptedData :" + EncryptedData);

		
		System.out.println("randomNumberiv :" + randomNumberiv);
	//	
		
		
	
		
		System.out.println("AES springboot :" + rest);
		
		restserverupload = aes.createProducts();
		
		System.out.println("AES Encrypted Data :" + restserverupload);
		
	
	}

}
