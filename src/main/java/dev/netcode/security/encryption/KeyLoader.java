package dev.netcode.security.encryption;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import dev.netcode.util.Result;

public class KeyLoader {

	public static PublicKey loadPublicKeyFromFile(Path file) throws IOException {
		String publicContent = new String(Files.readAllBytes(file));
		publicContent = publicContent.replace("\n", "").replace("\r", "");
		publicContent = publicContent.substring(26,publicContent.length()-24);
		return RSAEncrypter.generatePublicKeyFromString(Base64.getDecoder().decode(publicContent));
	}
	
	public static PrivateKey loadPrivateKeyFromFile(Path file) throws IOException {
		String privateContent = new String(Files.readAllBytes(file));
		privateContent = privateContent.replace("\n", "").replace("\r", "");
		privateContent = privateContent.substring(27,privateContent.length()-25);
		return RSAEncrypter.generatePrivateKeyFromString(Base64.getDecoder().decode(privateContent));
	}
	
	public static Result<PublicKey> loadPublicKeyFromEncryptedFile(Path file, String password) throws IOException {
		String publicContent = new String(Files.readAllBytes(file));
		var result = AESEncrypter.decrypt(publicContent, password);
		if(!result.wasSuccessful()) {
			return new Result<PublicKey>(null, "Loading PublicKey from file failed while decrypting key file: "+result.getError());
		}
		publicContent = result.get().replace("\n", "").replace("\r", "");
		publicContent = publicContent.substring(26,publicContent.length()-24);
		return new Result<PublicKey>(RSAEncrypter.generatePublicKeyFromString(Base64.getDecoder().decode(publicContent)), null);
	}
	
	public static Result<PrivateKey> loadPrivateKeyFromEncryptedFile(Path file, String password) throws IOException {
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
