package dev.netcode.security.identity;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.json.JSONObject;

import com.google.gson.Gson;

import dev.netcode.security.encryption.RSAEncrypter;
import lombok.Getter;

public class Signature {
	
	@Getter private String issuerName;
	@Getter private String issuerIdentityID;
	@Getter private String dataHash;
	@Getter private String signature;
	@Getter private String issueDate;
	
	public Signature(String issuerName, String issuerIdentityID, String dataHash) {
		this.issuerName = issuerName;
		this.issuerIdentityID = issuerIdentityID;
		this.dataHash = dataHash;
		SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");
		this.issueDate = sdf.format(new Date());
	}
	
	public boolean isValid(PublicKey publicKey, Identity identity) {
		if(!identity.getHash().contentEquals(dataHash)) {
			return false;
		}
		return RSAEncrypter.verifySignature(publicKey, getVerifiableDataString(), signature);
	}
	
	public void sign(PrivateKey privateKey) {
		signature = RSAEncrypter.sign(privateKey, getVerifiableDataString());
	}
	
	@Override
	public String toString() {
		return new Gson().toJson(this);
	}
	
	public String getVerifiableDataString() {
		JSONObject json = new JSONObject();
		json.put("issuerName", issuerName);
		json.put("issuerIdentityID", issuerIdentityID);
		json.put("dataHash", dataHash);
		json.put("issueDate", issueDate);
		return json.toString();
	}
}