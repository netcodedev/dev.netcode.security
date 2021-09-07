package dev.netcode.security.encryption;

/**
 * Base58 is similar to Base64 but uses only 58 different characters
 * to encode the message.
 * Base58 is used for example to encode Bitcoin wallet addresses.
 */
public class Base58 {
	
	private static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
			.toCharArray();
	private static final int BASE_58 = ALPHABET.length;
	private static final int BASE_256 = 256;

	private static final int[] INDEXES = new int[128];
	static {
		for (int i = 0; i < INDEXES.length; i++) {
			INDEXES[i] = -1;
		}
		for (int i = 0; i < ALPHABET.length; i++) {
			INDEXES[ALPHABET[i]] = i;
		}
	}
	
	/**
	 * Encodes a byte array input to Base58
	 * @param input byte array to be encoded
	 * @return Base58 encoded data as String
	 */
	public static String encode(byte[] input) {
		if (input.length == 0) {
			return "";
		}

		input = copyOfRange(input, 0, input.length);

		int zeroCount = 0;
		while (zeroCount < input.length && input[zeroCount] == 0) {
			++zeroCount;
		}
		byte[] temp = new byte[input.length * 2];
		int j = temp.length;

		int startAt = zeroCount;
		while (startAt < input.length) {
			byte mod = divmod58(input, startAt);
			if (input[startAt] == 0) {
				++startAt;
			}

			temp[--j] = (byte) ALPHABET[mod];
		}
		while (j < temp.length && temp[j] == ALPHABET[0]) {
			++j;
		}

		while (--zeroCount >= 0) {
			temp[--j] = (byte) ALPHABET[0];
		}

		byte[] output = copyOfRange(temp, j, temp.length);
		return new String(output);
	}

	/**
	 * Decodes a Base58 encoded input to byte array
	 * @param input String to be decoded
	 * @return decoded byte array
	 */
	public static byte[] decode(String input) {
		if (input.length() == 0) {
			return new byte[0];
		}

		byte[] input58 = new byte[input.length()];
		for (int i = 0; i < input.length(); ++i) {
			char c = input.charAt(i);

			int digit58 = -1;
			if (c >= 0 && c < 128) {
				digit58 = INDEXES[c];
			}
			if (digit58 < 0) {
				throw new RuntimeException("Not a Base58 input: " + input);
			}

			input58[i] = (byte) digit58;
		}

		int zeroCount = 0;
		while (zeroCount < input58.length && input58[zeroCount] == 0) {
			++zeroCount;
		}

		byte[] temp = new byte[input.length()];
		int j = temp.length;

		int startAt = zeroCount;
		while (startAt < input58.length) {
			byte mod = divmod256(input58, startAt);
			if (input58[startAt] == 0) {
				++startAt;
			}

			temp[--j] = mod;
		}
		while (j < temp.length && temp[j] == 0) {
			++j;
		}

		return copyOfRange(temp, j - zeroCount, temp.length);
	}

	/**
	 * Gets the remainer when applying division by {@link BASE_58}
	 * @param number input array
	 * @param startAt index
	 * @return the remainer when applying division by {@link BASE_58}
	 */
	private static byte divmod58(byte[] number, int startAt) {
		int remainder = 0;
		for (int i = startAt; i < number.length; i++) {
			int digit256 = (int) number[i] & 0xFF;
			int temp = remainder * BASE_256 + digit256;

			number[i] = (byte) (temp / BASE_58);

			remainder = temp % BASE_58;
		}

		return (byte) remainder;
	}

	/**
	 * Gets the remainer when applying division by {@link BASE_256}
	 * @param number input array
	 * @param startAt index
	 * @return the remainer when applying division by {@link BASE_256}
	 */
	private static byte divmod256(byte[] number58, int startAt) {
		int remainder = 0;
		for (int i = startAt; i < number58.length; i++) {
			int digit58 = (int) number58[i] & 0xFF;
			int temp = remainder * BASE_58 + digit58;

			number58[i] = (byte) (temp / BASE_256);

			remainder = temp % BASE_256;
		}

		return (byte) remainder;
	}

	/**
	 * Copies a range of bytes inside given byte array to new byte array
	 * @param source byte array from which the range should be taken
	 * @param from start index
	 * @param to end index
	 * @return elements in the given range of the source as byte array
	 */
	private static byte[] copyOfRange(byte[] source, int from, int to) {
		byte[] range = new byte[to - from];
		System.arraycopy(source, from, range, 0, range.length);

		return range;
	}
}