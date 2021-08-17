package com.icici.encryption;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Random;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.google.gson.Gson;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;



@Component
@RestController



public class AES 
{
	

	 RestTemplate restTemplate = new RestTemplate();
	 EncryptionApplication encryptionapp = new EncryptionApplication();
	//Production RMS Public
	
	 static   Logger logger = LoggerFactory.getLogger(AES.class);

	 
	//static final String PUBLIC_CERTIFICATE = "D:\\Icicicertificate\\icicipubliccert.cer";	
	//static final String PUBLIC_CERTIFICATE = "F:\\vijayarajan-pfxfile\\vijayarajan-pfxfiles\\RCMStestcert.crt";	

	static final String PUBLIC_CERTIFICATE = "/keypair/icicipubliccert.cer";	
	static final String KEYSTORE_FILE = "/keypair/RCMSTestcrt.p12";
	
	//Production RMS Private
        //static final String KEYSTORE_FILE = "D:\\Icicicertificate\\RCMSTestcrt.p12";
	static final String KEYSTORE_PWD = "lemon@11";
	static final String KEYSTORE_ALIAS = "RMS";
	static final String KEYSTORE_INSTANCE = "PKCS12";
	static final String ASYMM_CIPHER = "RSA/ECB/PKCS1Padding";	
	static String jsonstring;
	HttpEntity <String> entity;	
	private static final String SALT = "ssshhhhhhhhhhh!!!!";
	public static String returnvariable = "";
	
	public AES() {
		super();
	}


	public static String generateRandom(int prefix) {
		Random rand = new Random();
		long x = (long) (rand.nextDouble() * 100000000000000L);
		String s = String.valueOf(prefix) + String.format("%014d", x);
		return s;
		}
		
	public static String generateRandomTwo(int prefix) {
		Random rand = new Random();
		long x = (long) (rand.nextDouble() * 100000000000000L);
		String s = String.valueOf(prefix) + String.format("%014d", x);
		return s;
		}

	
	 private  String getString(byte[] bytes) throws UnsupportedEncodingException {
    	 return new String(bytes, "UTF-8");
    }
	 
	 private  byte[] getBytes(String str) throws UnsupportedEncodingException {
		   	return str.getBytes("UTF-8");
		   }
	 
	 public  PublicKey getPublicKey(String base64PublicKey){
	        PublicKey publicKey = null;
	        try{
	            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
	            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	            publicKey = keyFactory.generatePublic(keySpec);
	            logger.info("An public Message");
	            return publicKey;
	        } catch (NoSuchAlgorithmException e) {
	            logger.info("An public key1 Message"+e.toString());

	            e.printStackTrace();
	        } catch (InvalidKeySpecException e) {
	            e.printStackTrace();
	            logger.info("An public Message"+e.toString());

	        }
	        return publicKey;
	    }
	 
	public static String getRequestkey(String randomNUmber) throws NoSuchAlgorithmException, NoSuchPaddingException,
	InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {
	Cipher ci = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	X509Certificate cert = getCertificate(PUBLIC_CERTIFICATE);
	ci.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
	byte[] input = randomNUmber.getBytes("UTF-8");
	String key = Base64.getEncoder().encodeToString(ci.doFinal(input));
	return key;
	}
	
	public  static X509Certificate getCertificate(String path) {
		//logger.info("file is :" + path);
		X509Certificate cert = null;
		try {
		FileInputStream inputStream = new FileInputStream(path);
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		cert = (X509Certificate) f.generateCertificate(inputStream);
		
        logger.info("An x509 Message");

		inputStream.close();
		//logger.info("Certificate Public Key is :" + cert.getPublicKey());
		} catch (FileNotFoundException e) {
		e.printStackTrace();
        logger.error("An x5091 Message"+e.toString());

		} catch (Exception e) {
		e.printStackTrace();
        logger.error("An x509 Message"+e.getMessage());

		}
		return cert;
		}
	

	
	public static String getRequestData( String keyss,String ivKey, String strToEncrypt)
	throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
	InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {

		try {
		      IvParameterSpec ivspec = new IvParameterSpec(ivKey.getBytes("UTF-8"));
		      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		      KeySpec spec = new PBEKeySpec(keyss.toCharArray(), SALT.getBytes(), 1000, 256);
		      SecretKey tmp = factory.generateSecret(spec);
		      SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
		      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		      cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
		      strToEncrypt = ivKey + strToEncrypt;
	            logger.info("An requestdata Message");

		      return Base64.getEncoder()
		     .encodeToString(cipher.doFinal(strToEncrypt.getBytes()));
		    } catch (Exception e) {
	            logger.error("An data Message"+e.toString());
		      System.out.println("Error while encrypting: " + e.toString());
		    }
	return null;
	} 
	
	
	   
	   	  
	    public  byte[] getIVSpec(String encryptedData) {
	    	byte[] IV = Base64.getDecoder().decode(encryptedData.getBytes());
	    	byte[] resbyte = new byte[16];
	    	for (int i = 0; i < 16; i++) {
	    	resbyte[i] = IV[i];
	    	}	    	
	    	return resbyte;
	    	}
	
	  
	 
	    
	    public  String readFileAsString(String fileName) throws Exception 
	    { 
	      String data = ""; 
	      data = new String(Files.readAllBytes(Paths.get(fileName))); 
	      return data; 
	    } 
	    
	    
	    
	    
	    public String getProductList() {
	        HttpHeaders headers = new HttpHeaders();
	        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
	        entity = new HttpEntity<String>(headers);
	        return restTemplate.exchange("http://210.18.134.54/RCMS/icic_test_api.php", HttpMethod.GET, entity, String.class).getBody();
	     }
	    

  public String createProducts() {
	    	
	  try {
		//  String apikey = "d43d121f-745b-4c80-841c-648f4e2c5bfe";
	    	HttpHeaders headers = new HttpHeaders();
	   // 	headers.set("apikey",apikey);
	     	headers.setContentType(MediaType.APPLICATION_JSON);
	    	MultiValueMap<String,Object> map= new LinkedMultiValueMap<String, Object>();
	    	Responses staticvalues = new Responses();
	    	staticvalues.setRequestId("ICI1234");
	    	staticvalues.setService("APICreation");
	    	staticvalues.setEncryptedKey(encryptionapp.Encryptedkey);
	    	staticvalues.setOaepHashingAlgorithm("NONE");
	    	staticvalues.setIv(encryptionapp.randomNumberiv);
	    	staticvalues.setEncryptedData(encryptionapp.EncryptedData);
	    	staticvalues.setClientInfo("");
	    	staticvalues.setOptionalParam("");
	    	Gson gsonresponse = new Gson();
	    	gsonresponse.toJson(staticvalues);
	    	System.out.println("static values -->"+gsonresponse.toJson(staticvalues));   

	    	map.add("response", gsonresponse.toJson(staticvalues));
	    	HttpEntity<MultiValueMap<String, Object>> request = new HttpEntity<MultiValueMap<String, Object>>(map, headers);

	    	returnvariable = restTemplate.exchange("http://210.18.134.54/RCMS/icic_test_api1.php", HttpMethod.POST, request, String.class).getBody();
	    	
	    //	returnvariable = restTemplate.exchange("https://apibankingsandbox.icicibank.com/api/v1/TransactionsReportingforDSB", HttpMethod.POST, request, String.class).getBody();

	    	logger.info("An data cretae products Message"+returnvariable);

	    	return returnvariable;    	

	  }catch(Exception e) {
		  
		  logger.error("create product errors --->"+e.getMessage());
		  
	  }
	return null;
	
	    }
	  

	    
	    
	    
	
}
