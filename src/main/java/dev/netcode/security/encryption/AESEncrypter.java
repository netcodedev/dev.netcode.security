package dev.netcode.security.encryption;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import dev.netcode.util.Result;

public class AESEncrypter {

	public static SecretKeySpec getKey(String password) {
		MessageDigest sha = null;
		SecretKeySpec privateKey = null;
		try {
			byte[] key = password.getBytes("UTF-8");
			sha = MessageDigest.getInstance("SHA-256");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			privateKey = new SecretKeySpec(key, "AES");
		} catch(NoSuchAlgorithmException | UnsupportedEncodingException e) {
			e.printStackTrace();
		} 
		return privateKey;
	}
	
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
