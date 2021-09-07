package dev.netcode.security.encryption;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

/**
 * This class simplifies the process of RSA Encrypting data.
 * Using it you can generate RSA Keys and encrypt/decrypt data.
 */
public class RSAEncrypter {

	/**
	 * Generates a {@link KeyPair} with given size.
	 * The higher the size, the more secure the key can be considered.
	 * Size must be divisible by 2.
	 * @param size of the keys to be generated
	 * @return the generated {@link KeyPair}
	 */
	public static KeyPair generateKeyPair(int size) {
		KeyPairGenerator keygen = null;
		try {
			keygen = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		keygen.initialize(size, new SecureRandom());
		return keygen.generateKeyPair();
	}
	
	/**
	 * Decrypts RSA encrypted data
	 * @param cipher data to be decrypted
	 * @param privateKey to be used to decrypt the data
	 * @return decrypted data as UTF-8 encoded String
	 */
	public static String decrypt(byte[] cipher, PrivateKey privateKey) {
		byte[] dec = {};
		Cipher c;
		try {
			c = Cipher.getInstance("RSA");
			c.init(Cipher.DECRYPT_MODE, privateKey);
			dec = c.doFinal(cipher);
		} catch(Exception e) {
			System.out.println("Error while decrypting: " + e.getMessage());
			e.printStackTrace();
		}
		return new String(dec, StandardCharsets.UTF_8);
	}
	
	/**
	 * Encrypts a message using a RSA {@link PublicKey}
	 * @param message to be encrypted
	 * @param publicKey ised to encrypt the data
	 * @return byte array of encrypted data
	 */
	public static byte[] encrypt(String message, PublicKey publicKey) {
		Cipher cipher = null;
		byte[] encrypted = null;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.getMessage());
		}
		try {
			encrypted = cipher.doFinal(message.getBytes("UTF8"));
		} catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e) {
			System.out.println("Error while encrypting: " + e.getMessage());
		}
		return encrypted;
	}
	
	/**
	 * Generates a RSA signature for a given input. The signature can
	 * be used to make sure a message comes from a specific sender
	 * @param privateKey used to sign the data
	 * @param input data to be signed
	 * @return Signature as String
	 */
	public static String sign(PrivateKey privateKey, String input) {
		try {
			Signature privateSignature = Signature.getInstance("SHA256withRSA");
		    privateSignature.initSign(privateKey);
		    privateSignature.update(input.getBytes(StandardCharsets.UTF_8));
	
		    byte[] signature = privateSignature.sign();
		    return Base64.getEncoder().encodeToString(signature);
		} catch(Exception e) {
			System.err.println("Signing failed: "+e.getMessage());
			return null;
		}
	}
	
	/**
	 * Verifies that a given signature matches given data and a given public key.
	 * This process ensures that the data really comes from the sender 
	 * @param publicKey of the sender
	 * @param data original data 
	 * @param signature to be tested
	 * @return true if the signature matches the data and public key
	 */
	public static boolean verifySignature(PublicKey publicKey, String data, String signature) {
		try {
			Signature publicSignature = Signature.getInstance("SHA256withRSA");
		    publicSignature.initVerify(publicKey);
		    publicSignature.update(data.getBytes(StandardCharsets.UTF_8));
	
		    byte[] signatureBytes = Base64.getDecoder().decode(signature);
	
		    return publicSignature.verify(signatureBytes);
		} catch(Exception e) {
			return false;
		}
	}
	
	/**
	 * Generates a public key from byte array
	 * @param key byte array
	 * @return public key
	 */
	public static PublicKey generatePublicKeyFromString(byte[] key){
	    try{
	        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(key);
	        KeyFactory kf = KeyFactory.getInstance("RSA");

	        return kf.generatePublic(X509publicKey);
	    } catch(Exception e){
	        e.printStackTrace();
	        return null;
	    }
	}
	
	/**
	 * Generates a private key from byte array
	 * @param key byte array
	 * @return private key
	 */
	public static PrivateKey generatePrivateKeyFromString(byte[] key){
	    try{
	        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(key);
	        KeyFactory kf = KeyFactory.getInstance("RSA");

	        return kf.generatePrivate(pkcs8EncodedKeySpec);
	    } catch(Exception e){
	        e.printStackTrace();
	        return null;
	    }
	}
	
	/**
	 * Encodes a Key to a String representation.
	 * The key will be encoded to Base64
	 * @param key to transform
	 * @return String representation
	 */
	public static String keyToString(Key key) {
		if(key == null) {
			return "null";
		}
		return Base64.getEncoder().encodeToString(key.getEncoded());
	}
	
	/**
	 * Generates a fingerprint string of a public key.
	 * The key has to be X509 compatible.
	 * The fingerprint will be SHA-1 representation of the key
	 * @param key to get the fingerprint of
	 * @return the fingerprint
	 */
	public static String getFingerprint(PublicKey key) {
		try {
	        X509EncodedKeySpec pubkeyspec = new X509EncodedKeySpec(key.getEncoded());
	        return Base58.encode(MessageDigest.getInstance("SHA-1").digest(pubkeyspec.getEncoded()));
		} catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
}
