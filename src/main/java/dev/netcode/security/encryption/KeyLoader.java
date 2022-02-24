package dev.netcode.security.encryption;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import dev.netcode.util.Result;

/**
 * This class simplifies the process of loading Keys from files
 */
public class KeyLoader {

	/**
	 * Loads a Base64 encoded RSA public key from file
	 * @param file Path of the file containing the Base64 encoded public key
	 * @return the public key
	 * @throws IOException if the file can not be read
	 * @throws InvalidKeySpecException in case the loaded key is malformed or currupted
	 */
	public static PublicKey loadPublicKeyFromFile(Path file) throws IOException, InvalidKeySpecException {
		String publicContent = new String(Files.readAllBytes(file));
		publicContent = publicContent.replace("\n", "").replace("\r", "");
		publicContent = publicContent.substring(26,publicContent.length()-24);
		return RSAEncrypter.generatePublicKeyFromString(Base64.getDecoder().decode(publicContent));
	}
	

	/**
	 * Loads a Base64 encoded RSA private key from file
	 * @param file Path of the file containing the Base64 encoded private key
	 * @return the private key
	 * @throws IOException if the file can not be read
	 * @throws InvalidKeySpecException in case the loaded key is malformed or currupted
	 */
	public static PrivateKey loadPrivateKeyFromFile(Path file) throws IOException, InvalidKeySpecException {
		String privateContent = new String(Files.readAllBytes(file));
		privateContent = privateContent.replace("\n", "").replace("\r", "");
		privateContent = privateContent.substring(27,privateContent.length()-25);
		return RSAEncrypter.generatePrivateKeyFromString(Base64.getDecoder().decode(privateContent));
	}
	

	/**
	 * Loads a Base64 encoded RSA public key from an encrypted file
	 * @param file Path of the file containing the Base64 encoded public key
	 * @param password used to decrypt the file
	 * @return the public key
	 * @throws IOException if the file can not be read
	 * @throws InvalidKeySpecException in case the loaded key is malformed or currupted
	 */
	public static Result<PublicKey> loadPublicKeyFromEncryptedFile(Path file, String password) throws IOException, InvalidKeySpecException {
		String publicContent = new String(Files.readAllBytes(file));
		var result = AESEncrypter.decrypt(publicContent, password);
		if(!result.wasSuccessful()) {
			return new Result<PublicKey>(null, "Loading PublicKey from file failed while decrypting key file: "+result.getError());
		}
		publicContent = result.get().replace("\n", "").replace("\r", "");
		publicContent = publicContent.substring(26,publicContent.length()-24);
		return new Result<PublicKey>(RSAEncrypter.generatePublicKeyFromString(Base64.getDecoder().decode(publicContent)), null);
	}
	
	/**
	 * Loads a Base64 encoded RSA private key from an encrypted file
	 * @param file Path of the file containing the Base64 encoded private key
	 * @param password used to decrypt the file
	 * @return the private key
	 * @throws IOException if the file can not be read
	 * @throws InvalidKeySpecException in case the loaded key is malformed or currupted
	 */
	public static Result<PrivateKey> loadPrivateKeyFromEncryptedFile(Path file, String password) throws IOException, InvalidKeySpecException {
		String privateContent = new String(Files.readAllBytes(file));
		var result = AESEncrypter.decrypt(privateContent, password);
		if(!result.wasSuccessful()) {
			return new Result<PrivateKey>(null, "Loading PrivateKey from file failed while decrypting key file: "+result.getError());
		}
		privateContent = result.get().replace("\n", "").replace("\r", "");
		privateContent = privateContent.substring(27,privateContent.length()-25);
		return new Result<PrivateKey>(RSAEncrypter.generatePrivateKeyFromString(Base64.getDecoder().decode(privateContent)),null);
	}
}
