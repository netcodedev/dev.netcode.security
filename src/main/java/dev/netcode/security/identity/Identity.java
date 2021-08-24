package dev.netcode.security.identity;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import dev.netcode.security.encryption.AESEncrypter;
import dev.netcode.security.encryption.RSAEncrypter;
import dev.netcode.util.StringUtils;
import lombok.Getter;
import lombok.Setter;

public class Identity {

	@Getter private String possessor;
	@Getter private String publicKey;
	@Getter private String privateKey;
	@Getter private String identityID;
	@Getter private HashMap<String, String> data;
	@Getter @Setter private Signature signature;
	@Getter private transient KeyPair keyPair;
	
	public Identity(String possessor, HashMap<String, String> data, String password) {
		this.possessor = possessor;
		this.data = data;
		this.keyPair = RSAEncrypter.generateKeyPair(4096);
		this.publicKey = RSAEncrypter.getStringFromKey(keyPair.getPublic());
		this.privateKey = AESEncrypter.encrypt(RSAEncrypter.getStringFromKey(keyPair.getPrivate()), password).get();
		this.identityID = RSAEncrypter.getFingerprintFromPublicKeyString(RSAEncrypter.getStringFromKey(keyPair.getPublic()));
	}
	
	public static Identity load(Path path) {
		try {
			if(!path.toFile().exists()) {
				System.err.println("File not found!");
				return null;
			}
			String fileContent = new String(Files.readAllBytes(path));
			return new Gson().fromJson(fileContent, Identity.class);
		} catch (IOException e) {
			System.err.println("Failed to load Identity from file: "+e.getMessage());
			return null;
		}
	}
	
	public boolean save(Path path) {
		try {
			Gson gsonBuilder = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
			String identityString = new String(gsonBuilder.toJson(this).getBytes(StandardCharsets.UTF_8),StandardCharsets.ISO_8859_1);
			BufferedWriter fileWriter = new BufferedWriter(new FileWriter(path.toFile()));
			fileWriter.write(identityString);
			fileWriter.close();
			return true;
		} catch(Exception e) {
			System.err.println("Failed to save Identity to file: "+e.getMessage());
			return false;
		}
	}
	
	public boolean unlock(String password) {
		var result = AESEncrypter.decrypt(this.privateKey, password);
		if(result.wasSuccessful()) {
			this.keyPair = new KeyPair(
					RSAEncrypter.generatePublicKeyFromString(Base64.getDecoder().decode(this.publicKey)),
					RSAEncrypter.generatePrivateKeyFromString(Base64.getDecoder().decode(result.get()))
					);
			return true;
		}
		return false;
	}
	
	public boolean isValid(PublicKey publicKey) {
		if(signature == null) {
			return false;
		}
		return signature.isValid(publicKey, this);
	}
	
	public boolean isUnlocked() {
		return this.keyPair!=null;
	}
	
	public String getHash() {
		return StringUtils.applySha256(identityID+possessor+new Gson().toJson(data));
	}
	
	@Override
	public String toString() {
		return new Gson().toJson(this);
	}
	
	public String toIndentedString() {
		return new GsonBuilder().setPrettyPrinting().create().toJson(this);
	}
	
}
