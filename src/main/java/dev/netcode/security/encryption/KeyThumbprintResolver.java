package dev.netcode.security.encryption;

import java.security.PublicKey;

public interface KeyThumbprintResolver {

	public PublicKey resolve(String thumbprint);
	
}
