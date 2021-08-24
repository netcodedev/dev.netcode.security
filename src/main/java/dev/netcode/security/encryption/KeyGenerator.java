package dev.netcode.security.encryption;

import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import dev.netcode.util.StringUtils;

public class KeyGenerator {

	public static boolean GenerateKeys(int size, Path publicKeyFile, Path privateKeyFile) throws FileNotFoundException {
		if(!isPowerOfTwo(size)) {
			throw new IllegalArgumentException("Size must be a power of 2");
		}
		KeyPair keyPair = RSAEncrypter.generateKeyPair(size);
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		
		//Saving Public Key
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
		String publicKeyString = "-----BEGIN PUBLIC KEY-----\n"+
				new String(StringUtils.chunkSplit(new String(Base64.getEncoder().encode(x509EncodedKeySpec.getEncoded())),64,'\n'))+
				"-----END PUBLIC KEY-----";
		if(!StringUtils.saveToFile(publicKeyFile, publicKeyString)) {
			return false;
		}
		
		//Saving Private Key
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		String privateKeyString = "-----BEGIN PRIVATE KEY-----\n"+
				new String(StringUtils.chunkSplit(new String(Base64.getEncoder().encode(pkcs8EncodedKeySpec.getEncoded())),64,'\n'))+
				"-----END PRIVATE KEY-----";
		return StringUtils.saveToFile(privateKeyFile, privateKeyString);
	}
	
	public static boolean GenerateKeys(int size, Path publicKeyFile, Path privateKeyFile, String password) throws FileNotFoundException {
		if(!isPowerOfTwo(size)) {
			throw new IllegalArgumentException("Size must be a power of 2");
		}
		KeyPair keyPair = RSAEncrypter.generateKeyPair(size);
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		
		//Saving Public Key
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
		String publicKeyString = "-----BEGIN PUBLIC KEY-----\n"+
				new String(StringUtils.chunkSplit(new String(Base64.getEncoder().encode(x509EncodedKeySpec.getEncoded())),64,'\n'))+
				"-----END PUBLIC KEY-----";
		var encrypted = AESEncrypter.encrypt(publicKeyString, password);
		if(!encrypted.wasSuccessful()) {
			return false;
		}
		if(!StringUtils.saveToFile(publicKeyFile, encrypted.get())) {
			return false;
		}
		
		//Saving Private Key
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		String privateKeyString = "-----BEGIN PRIVATE KEY-----\n"+
				new String(StringUtils.chunkSplit(new String(Base64.getEncoder().encode(pkcs8EncodedKeySpec.getEncoded())),64,'\n'))+
				"-----END PRIVATE KEY-----";
		encrypted = AESEncrypter.encrypt(privateKeyString,password);
		if(!encrypted.wasSuccessful()) {
			return false;
		}
		return StringUtils.saveToFile(privateKeyFile, encrypted.get());
	}
	
	private static boolean isPowerOfTwo(int x) {
	    return (x != 0) && ((x & (x - 1)) == 0);
	}
}
