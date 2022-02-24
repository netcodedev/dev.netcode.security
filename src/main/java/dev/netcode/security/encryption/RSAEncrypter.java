package dev.netcode.security.encryption;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
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
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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
	 * @throws InvalidKeyException in case the key format is not supported
	 * @throws BadPaddingException in case something failed while padding
	 * @throws IllegalBlockSizeException in case the blocksize is invalid
	 */
	public static String decrypt(byte[] cipher, PrivateKey privateKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException  {
		byte[] dec = {};
		Cipher c = null;
		try {
			c = Cipher.getInstance("RSA");
		} catch (NoSuchAlgorithmException |NoSuchPaddingException e) {
			// RSA exists so this should never be thrown
			e.printStackTrace();
		}
		c.init(Cipher.DECRYPT_MODE, privateKey);
		dec = c.doFinal(cipher);
		return new String(dec, StandardCharsets.UTF_8);
	}
	
	/**
	 * Encrypts a message using a RSA {@link PublicKey}
	 * @param message to be encrypted
	 * @param publicKey ised to encrypt the data
	 * @return byte array of encrypted data
	 * @throws InvalidKeyException in case the key format is not supported
	 * @throws BadPaddingException in case something failed while padding
	 * @throws IllegalBlockSizeException in case the blocksize is invalid
	 */
	public static byte[] encrypt(String message, PublicKey publicKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = null;
		byte[] encrypted = null;
		try {
			cipher = Cipher.getInstance("RSA");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// RSA exists so this should never be thrown
			e.printStackTrace();
		}
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
		return encrypted;
	}
	
	/**
	 * Generates a RSA signature for a given input. The signature can
	 * be used to make sure a message comes from a specific sender
	 * @param privateKey used to sign the data
	 * @param input data to be signed
	 * @return Signature as String
	 * @throws InvalidKeyException in case the key format is not supported
	 * @throws SignatureException in case something went wrong while creating the signature
	 */
	public static String sign(PrivateKey privateKey, String input) throws InvalidKeyException, SignatureException {
		Signature privateSignature = null;
		try {
			privateSignature = Signature.getInstance("SHA256withRSA");
		} catch (NoSuchAlgorithmException e) {
			// SHA256withRSA exists so this should never be thrown
			e.printStackTrace();
		}
	    privateSignature.initSign(privateKey);
	    privateSignature.update(input.getBytes(StandardCharsets.UTF_8));

	    byte[] signature = privateSignature.sign();
	    return Base64.getEncoder().encodeToString(signature);
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
	 * @throws InvalidKeySpecException in case the key format is not supported
	 */
	public static PublicKey generatePublicKeyFromString(byte[] key) throws InvalidKeySpecException{
        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(key);
        KeyFactory kf;
		try {
			kf = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			//should never be thrown
			e.printStackTrace();
			return null;
		}
		return kf.generatePublic(X509publicKey);
	}
	
	/**
	 * Generates a private key from byte array
	 * @param key byte array
	 * @return private key
	 * @throws InvalidKeySpecException in case the key format is not supported
	 */
	public static PrivateKey generatePrivateKeyFromString(byte[] key) throws InvalidKeySpecException{
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory kf;
		try {
			kf = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			// should never be thrown
			e.printStackTrace();
			return null;
		}
	    return kf.generatePrivate(pkcs8EncodedKeySpec);
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
