package dev.netcode.security.identity;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.json.JSONObject;

import com.google.gson.Gson;

import dev.netcode.security.encryption.RSAEncrypter;
import lombok.Getter;

/**
 * Signatures can be used to add prove to an Identity that the contained data
 * either comes from or was checked by a specific person, institution or service
 */
public class Signature {
	
	@Getter private String issuerName;
	@Getter private String issuerIdentityID;
	@Getter private String dataHash;
	@Getter private String signature;
	@Getter private String issueDate;
	
	/**
	 * Creates a raw signature that is not signed yet.
	 * @param issuerName name of the issuer
	 * @param issuerIdentityID unique identifier of the issuer
	 * @param dataHash of the data to be signed
	 */
	public Signature(String issuerName, String issuerIdentityID, String dataHash) {
		this.issuerName = issuerName;
		this.issuerIdentityID = issuerIdentityID;
		this.dataHash = dataHash;
		SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");
		this.issueDate = sdf.format(new Date());
	}
	
	/**
	 * Checks the validity of the signature
	 * @param publicKey of the instance that should have signed the data
	 * @param identity the signature should belong to
	 * @return true if the signature is valid and belongs to the given identity
	 */
	public boolean isValid(PublicKey publicKey, Identity identity) {
		if(!identity.getHash().contentEquals(dataHash)) {
			return false;
		}
		return RSAEncrypter.verifySignature(publicKey, getVerifiableDataString(), signature);
	}
	
	/**
	 * Signs this Signature which makes it valid.
	 * @param privateKey used to sign the signature
	 */
	public void sign(PrivateKey privateKey) {
		signature = RSAEncrypter.sign(privateKey, getVerifiableDataString());
	}
	
	@Override
	/**
	 * Creates a string representation of this signature
	 */
	public String toString() {
		return new Gson().toJson(this);
	}
	
	/**
	 * @return all the data contained in the signature that is verifiable
	 */
	public String getVerifiableDataString() {
		JSONObject json = new JSONObject();
		json.put("issuerName", issuerName);
		json.put("issuerIdentityID", issuerIdentityID);
		json.put("dataHash", dataHash);
		json.put("issueDate", issueDate);
		return json.toString();
	}
}