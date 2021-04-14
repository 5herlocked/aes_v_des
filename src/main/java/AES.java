import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class AES {
	private int keyLength;
	private int rounds;
	private IvParameterSpec IV;
	private SecretKey generatedKey;

	public AES (int keyLength) throws NoSuchAlgorithmException {
		this.keyLength = keyLength;

		if (keyLength == 128) {
			this.rounds = 10;
		}
		else if (keyLength == 192) {
			this.rounds = 12;
		}
		else if (keyLength == 256) {
			this.rounds = 14;
		}
		else {
			this.keyLength = 128;
			this.rounds = 10;
		}

		this.IV = generateIV();

		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(this.keyLength);
		this.generatedKey = keyGen.generateKey();
	}

	private IvParameterSpec generateIV () throws NoSuchAlgorithmException {
		byte[] IV = new byte[16];
		SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
		prng.nextBytes(IV);

		return new IvParameterSpec(IV);
	}


	public byte[] encrypt (String plainText) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte[] clean = plainText.getBytes(StandardCharsets.UTF_8);

		// Key derived from the hash of the message
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update(generatedKey.toString().getBytes(StandardCharsets.UTF_8));
		byte[] keyBytes = new byte[16];
		System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

		// encrypt
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, IV);
		byte[] encrypted = cipher.doFinal(clean);

		// Combine IV and encrypted part
		byte[] encryptedIVAndText = new byte[16 + encrypted.length];
		System.arraycopy(IV.getIV(), 0, encryptedIVAndText, 0, 16);
		System.arraycopy(encrypted, 0, encryptedIVAndText, 16, encrypted.length);

		return encryptedIVAndText;
	}

	public byte[] decrypt (byte[] cipherTextAndIV, String key) throws NoSuchAlgorithmException {

		// Extract IV
		byte[] iv = new byte[16];
		System.arraycopy(cipherTextAndIV, 0, iv, 0, iv.length);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

		// Isolate CipherText
		int encryptedSize = cipherTextAndIV.length - 16;
		byte[] encryptedBytes = new byte[encryptedSize];
		System.arraycopy(cipherTextAndIV, 16, encryptedBytes, 0, encryptedSize);

		// Hash Key
		byte[] keyBytes = new byte[keyLength/8];
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(keyBytes);
	}
}
