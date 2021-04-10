import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.charset.*;
import java.security.*;

public class Rijndael {

	private int keyLength;

	private int rounds;

	private SecretKey generatedKey;

	private byte[][] SBox;

	public Rijndael (int keyLength, int rounds) {
		this.keyLength = keyLength;
		this.rounds = rounds;
		this.SBox = new byte[16][16];
	}

	public void generateKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

		keyGenerator.init(keyLength);

		this.generatedKey = keyGenerator.generateKey();
	}

	public void initialiseSBox() {
		byte p = 1, q = 1;

		do {
			p = (byte) (p ^ (p << 1) ^ ((p & 0x80) != 0x0 ? 0x1B : 0x0));

			q ^= q << 1;
			q ^= q << 2;
			q ^= q << 4;

			q ^= (q & 0x80) != 0x0 ? 0x09 : 0x0;

			// Compute the Affine Transform
			byte xFormed = (byte) (q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4));
			int valP = (int) Math.sqrt(p);
			SBox[valP][valP] = (byte) (xFormed ^ 0x63);

		} while (p != 1);

		// SPECIAL CASE since 0 has no inverse
		SBox[0][0] = 0x63;
	}

	// Rotates BYTE x LEFT
	private byte ROTL8(byte x, int times) {
		return (byte) (x << times | x >> (8 - times));
	}

	private byte[] generateRoundKeys() {
		// ROTWORD is just ROTL8(x, 1)

	}

	public byte[] encrypt(String plainText) throws
		InvalidAlgorithmParameterException, InvalidKeyException,
		NoSuchAlgorithmException, NoSuchPaddingException,
		UnsupportedEncodingException, BadPaddingException,
		IllegalBlockSizeException {
		byte[] clean = plainText.getBytes();

		if (this.generatedKey == null) {
			this.generateKey();
		}

		// Generating IV
		int ivSize = 16;
		byte[] iv = new byte[ivSize];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

		// Hashing key.
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update(generatedKey.toString().getBytes(StandardCharsets.UTF_8));
		byte[] keyBytes = new byte[16];
		System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

		// Encrypt.
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
		byte[] encrypted = cipher.doFinal(clean);

		// Combine IV and encrypted part.
		byte[] encryptedIVAndText = new byte[ivSize + encrypted.length];
		System.arraycopy(iv, 0, encryptedIVAndText, 0, ivSize);
		System.arraycopy(encrypted, 0, encryptedIVAndText, ivSize, encrypted.length);

		return encryptedIVAndText;
	}

	public String decrypt(byte[] encryptedIvTextBytes, String key) throws
		NoSuchAlgorithmException, NoSuchPaddingException,
		BadPaddingException, IllegalBlockSizeException,
		InvalidAlgorithmParameterException, InvalidKeyException {
		int ivSize = 16;
		int keySize = 16;

		// Extract IV.
		byte[] iv = new byte[ivSize];
		System.arraycopy(encryptedIvTextBytes, 0, iv, 0, iv.length);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

		// Extract encrypted part.
		int encryptedSize = encryptedIvTextBytes.length - ivSize;
		byte[] encryptedBytes = new byte[encryptedSize];
		System.arraycopy(encryptedIvTextBytes, ivSize, encryptedBytes, 0, encryptedSize);

		// Hash key.
		byte[] keyBytes = new byte[keySize];
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(key.getBytes());
		System.arraycopy(md.digest(), 0, keyBytes, 0, keyBytes.length);
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

		// Decrypt.
		Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/NoPadding");
		cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
		byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);

		return new String(decrypted);
	}
}
