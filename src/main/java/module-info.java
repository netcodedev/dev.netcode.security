module dev.netcode.security {
	requires dev.netcode.util;
	requires lombok;
	requires org.json;
	requires com.google.gson;
	
	exports dev.netcode.security.encryption;
	exports dev.netcode.security.identity;
}