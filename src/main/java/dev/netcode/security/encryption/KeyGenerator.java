package dev.netcode.security.encryption;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import dev.netcode.util.StringUtils;

/**
 * This class can be used to generate RSA cryptographic keys and safe them to file
 * @see RSAEncrypter
 */
public class KeyGenerator {

	/**
	 * Generates RSA Keys of given size and saves them to files
	 * @param size of the keys (the bigger, the more secure)
	 * @param publicKeyFile Path to the file the public key will be saved to. 
	 * File will be created if it doesn't already exist
	 * @param privateKeyFile Path to the file the private key will be saved to. 
	 * File will be created if it doesn't already exist
	 * @return true if everything was completed successfully. false otherwise
	 */
	public static boolean generateKeys(int size, Path publicKeyFile, Path privateKeyFile) {
		if(!isPowerOfTwo(size)) {
			throw new IllegalArgumentException("Size must be a power of 2");
		}
		KeyPair keyPair = RSAEncrypter.generateKeyPair(size);
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		
		//Saving Public Key
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
		String publicKeyString = "-----BEGIN PUBLIC KEY-----\n"+
				new String(StringUtils.chunkInsert(new String(Base64.getEncoder().encode(x509EncodedKeySpec.getEncoded())),64,'\n'))+
				"-----END PUBLIC KEY-----";
		if(!StringUtils.saveToFile(publicKeyFile, publicKeyString)) {
			return false;
		}
		
		//Saving Private Key
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		String privateKeyString = "-----BEGIN PRIVATE KEY-----\n"+
				new String(StringUtils.chunkInsert(new String(Base64.getEncoder().encode(pkcs8EncodedKeySpec.getEncoded())),64,'\n'))+
				"-----END PRIVATE KEY-----";
		return StringUtils.saveToFile(privateKeyFile, privateKeyString);
	}
	
	/**
	 * Generates RSA Keys of given size, encrypts them using AES and saves them to files
	 * @param size of the keys (the bigger, the more secure)
	 * @param publicKeyFile Path to the file the public key will be saved to. 
	 * File will be created if it doesn't already exist
	 * @param privateKeyFile Path to the file the private key will be saved to. 
	 * File will be created if it doesn't already exist
	 * @param password to be used to encrypt the keys
	 * @return true if everything was completed successfully. false otherwise
	 */
	public static boolean generateKeys(int size, Path publicKeyFile, Path privateKeyFile, String password) {
		if(!isPowerOfTwo(size)) {
			throw new IllegalArgumentException("Size must be a power of 2");
		}
		KeyPair keyPair = RSAEncrypter.generateKeyPair(size);
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		
		//Saving Public Key
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
		String publicKeyString = "-----BEGIN PUBLIC KEY-----\n"+
				new String(StringUtils.chunkInsert(new String(Base64.getEncoder().encode(x509EncodedKeySpec.getEncoded())),64,'\n'))+
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
				new String(StringUtils.chunkInsert(new String(Base64.getEncoder().encode(pkcs8EncodedKeySpec.getEncoded())),64,'\n'))+
				"-----END PRIVATE KEY-----";
		encrypted = AESEncrypter.encrypt(privateKeyString,password);
		if(!encrypted.wasSuccessful()) {
			return false;
		}
		return StringUtils.saveToFile(privateKeyFile, encrypted.get());
	}
	
	/**
	 * @param x number that should be checked
	 * @return true if the given number is a power of two
	 */
	private static boolean isPowerOfTwo(int x) {
	    return (x != 0) && ((x & (x - 1)) == 0);
	}
}
