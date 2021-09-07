package dev.netcode.security.identity;

import java.io.BufferedWriter;
import java.io.FileNotFoundException;
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

/**
 * Identity instances are meant to contain data about a person, institution
 * or service which is signed by a trusted authority.
 * Identities can also be self-signed which does not provide any layer of trust
 * if not used by a trusted authority. This means trusted authorities must obviously
 * sign their identities by themselves.
 * An Identity can be used to encrypt, decrypt and sign data
 * The class is designed to be safely serializable so instances can easily be stored on disk.
 * The private parts should be password encrypted.
 */
public class Identity {

	@Getter private String possessor;
	@Getter private String publicKey;
	@Getter private String privateKey;
	@Getter private String identityID;
	@Getter private HashMap<String, String> data;
	@Getter @Setter private Signature signature;
	@Getter private transient KeyPair keyPair;
	
	/**
	 * Creates an identity from the given data
	 * @param possessor name of the person, institution or service that possesses the identity
	 * @param data key-value pairs of data containing information about the possessor
	 * @param password which should be used to encrypt the private parts
	 */
	public Identity(String possessor, HashMap<String, String> data, String password) {
		this.possessor = possessor;
		this.data = data;
		this.keyPair = RSAEncrypter.generateKeyPair(4096);
		this.publicKey = RSAEncrypter.keyToString(keyPair.getPublic());
		this.privateKey = AESEncrypter.encrypt(RSAEncrypter.keyToString(keyPair.getPrivate()), password).get();
		this.identityID = RSAEncrypter.getFingerprint(keyPair.getPublic());
	}
	
	/**
	 * Loads an Identity from a file
	 * @param path of the identity file
	 * @return identity instance
	 */
	public static Identity load(Path path) {
		try {
			if(!path.toFile().exists()) {
				throw new FileNotFoundException("File \""+path.toFile().getAbsolutePath()+"\" doesn't exist");
			}
			String fileContent = new String(Files.readAllBytes(path));
			return new Gson().fromJson(fileContent, Identity.class);
		} catch (IOException e) {
			throw new RuntimeException("Failed to load Identity from file: "+e.getMessage());
		}
	}
	
	/**
	 * Saves the Identity to file at a given path.<br>
	 * Inexistent files will be created.
	 * Existent files will be overridden.
	 * @param path of the file to save the Identity to
	 * @return true if the process was successful
	 */
	public boolean save(Path path) {
		try {
			Gson gsonBuilder = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
			String identityString = new String(gsonBuilder.toJson(this).getBytes(StandardCharsets.UTF_8),StandardCharsets.ISO_8859_1);
			BufferedWriter fileWriter = new BufferedWriter(new FileWriter(path.toFile()));
			fileWriter.write(identityString);
			fileWriter.close();
			return true;
		} catch(Exception e) {
			throw new RuntimeException("Failed to save Identity to file: "+e.getMessage());
		}
	}
	
	/**
	 * Unlocks a loaded identity which makes it possible to use it
	 * @param password to unlock the identity with
	 * @return true if the unlocking process was successful
	 */
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
	
	/**
	 * Checks if the {@link Signature} of the identity is valid 
	 * using a given public key.
	 * @param publicKey to test the signature against
	 * @return true if the signature is valid, false otherwise
	 */
	public boolean isValid(PublicKey publicKey) {
		if(signature == null) {
			return false;
		}
		return signature.isValid(publicKey, this);
	}
	
	/**
	 * @return true if the identity is unlocked and usable
	 */
	public boolean isUnlocked() {
		return this.keyPair!=null;
	}
	
	/**
	 * Hashes the information contained in the identity using SHA-256
	 * @return the hashed information
	 */
	public String getHash() {
		return StringUtils.applySha256(identityID+possessor+new Gson().toJson(data));
	}
	
	/**
	 * Generates a String representation of this identity containing
	 * the data that is secure to be sent.
	 */
	@Override
	public String toString() {
		return new Gson().toJson(this);
	}
	
	/**
	 * Like {@link #toString()} but idents certain parts to make it better readable
	 * @return idented String representation
	 */
	public String toIndentedString() {
		return new GsonBuilder().setPrettyPrinting().create().toJson(this);
	}
	
}
