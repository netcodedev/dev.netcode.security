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

public class RSAEncrypter {

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
	
	public static String decrypt(byte[] cipher, PrivateKey pk) {
		byte[] dec = {};
		Cipher c;
		try {
			c = Cipher.getInstance("RSA");
			c.init(Cipher.DECRYPT_MODE, pk);
			dec = c.doFinal(cipher);
		} catch(Exception e) {
			System.out.println("Error while decrypting: " + e.getMessage());
			e.printStackTrace();
		}
		return bytes2String(dec);
	}
	
	public static String decryptBase64Array(String[] parts, PrivateKey pk) {
		String decrypted = "";
		
		Cipher c;
		try {
			c = Cipher.getInstance("RSA");
			c.init(Cipher.DECRYPT_MODE, pk);
			for(String part : parts) {
				decrypted += bytes2String(c.doFinal(Base64.getDecoder().decode(part)));
			}
		} catch(Exception e) {
			System.out.println("Error while decrypting: " + e.getMessage());
		}
		return decrypted;
	}
	
	public static byte[] encrypt(String message, PublicKey pk) {
		Cipher cipher = null;
		byte[] encrypted = null;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, pk);
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
	
	public static PublicKey generatePublicKeyFromString(String key){
	    try{
	        byte[] byteKey = hexStringToByteArray(key);
	        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
	        KeyFactory kf = KeyFactory.getInstance("RSA");

	        return kf.generatePublic(X509publicKey);
	    } catch(Exception e){
	        e.printStackTrace();
	        return null;
	    }
	}
	
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
	
	public static PrivateKey generatePrivateKeyFromString(String key){
	    try{
	        byte[] byteKey = key.getBytes();
	        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(byteKey);
	        KeyFactory kf = KeyFactory.getInstance("RSA");

	        return kf.generatePrivate(pkcs8EncodedKeySpec);
	    } catch(Exception e){
	        e.printStackTrace();
	        return null;
	    }
	}
	
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
	
	public static String getStringFromKey(Key key) {
		if(key == null) {
			return "null";
		}
		return Base64.getEncoder().encodeToString(key.getEncoded());
	}
	
	public static String getFingerprintFromPublicKeyString(String key) {
		try {
			byte[] byteKey = hexStringToByteArray(key);
	        X509EncodedKeySpec pubkeyspec = new X509EncodedKeySpec(byteKey);
	        return Base58.encode(MessageDigest.getInstance("SHA-1").digest(pubkeyspec.getEncoded()));
		} catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static String bytes2String(byte[] bytes) {
		StringBuilder string = new StringBuilder();
		for (byte b : bytes) {
			String hexString = Integer.toHexString(0x00FF & b);
			string.append(hexString.length() == 1 ? "0" + hexString : hexString);
		}
		return string.toString();
	}
	
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	public static String hexToString(String hexStr) {
	    StringBuilder output = new StringBuilder("");
	     
	    for (int i = 0; i < hexStr.length(); i += 2) {
	        String str = hexStr.substring(i, i + 2);
	        output.append((char) Integer.parseInt(str, 16));
	    }
	     
	    return output.toString();
	}
}
