package dev.netcode.security.encryption;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import dev.netcode.util.Result;

/**
 * This utility class can be used to encrypt and decrypt data using
 * the AES encryption algorithm. 
 */
public class AESEncrypter {

	/**
	 * Generates a {@link SecretKeySpec} from a password to be used for
	 * AES encryption
	 * @param password to generate the {@link SecretKeySpec} for
	 * @return the generated {@link SecretKeySpec}
	 */
	public static SecretKeySpec getKey(String password) {
		MessageDigest sha = null;
		SecretKeySpec privateKey = null;
		byte[] key = password.getBytes(StandardCharsets.UTF_8);
		try {
			sha = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			// SHA-256 exists so this should never be thrown
			e.printStackTrace();
		}
		key = sha.digest(key);
		key = Arrays.copyOf(key, 16);
		privateKey = new SecretKeySpec(key, "AES");
		return privateKey;
	}
	
	/**
	 * Encrypts a message using a given password and returns it as
	 * Base64 encrypted String.
	 * For encryption the cipher instance of <code>AES/ECB/PKCS5PADDING</code> is used
	 * @param message to be encrypted
	 * @param password to be used to encrypt the message
	 * @return encrypted message wrapped inside {@link Result}
	 */
	public static Result<String> encrypt(String message, String password){
		String encrypted = null;
		try {
			SecretKeySpec key = getKey(password);
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			encrypted = Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes("UTF-8")));
		} catch(Exception e) {
			return new Result<String>(null, "Error while encrypting: "+e.getMessage());
		}
		return new Result<String>(encrypted, null);
	}
	
	/**
	 * Decrypts a message using a given password and returns it as String.
	 * It is assumed that the message is encrypted using <code>AES/ECB/PKCS5PADDING</code>
	 * and transformed to Base64.
	 * @param message to be decrypted
	 * @param password to be used to decrypt the message
	 * @return decrypted message wrapped inside {@link Result}
	 */
	public static Result<String> decrypt(String message, String password) {
		String decrypted = null;
		try {
			SecretKeySpec key = getKey(password);
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, key);
			decrypted = new String(cipher.doFinal(Base64.getDecoder().decode(message)));
		} catch(Exception e) {
			return new Result<String>(null, "Error while decrypting: "+e.getMessage());
		}
		return new Result<String>(decrypted, null);
	}
}
