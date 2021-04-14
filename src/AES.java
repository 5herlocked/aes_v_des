import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

public class AES {
	// Instance variables
	private SecureRandom sRandom = new SecureRandom();
	private Cipher cipher;
	private IvParameterSpec IV;
	private SecretKey key;
	private int keyLength;

	// Constructor
	// Accepts the keyLength in bits (128/192/256)
	public AES(int keyLength) throws NoSuchPaddingException, NoSuchAlgorithmException {
		switch (keyLength) {
			case 192 -> this.keyLength = 192;
			case 256 -> this.keyLength = 256;
			default -> this.keyLength = 128;
		}

		this.cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		this.IV = generateIV();
		this.key = generateKey();
	}

	// Getters
	public Cipher getCipher () {
		return cipher;
	}

	public IvParameterSpec getIV () {
		return IV;
	}

	public SecretKey getKey () {
		return key;
	}

	// Private Methods
	private SecretKey generateKey () throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(this.keyLength);

		return keyGenerator.generateKey();
	}

	private IvParameterSpec generateIV () {
		byte[] byteIV = new byte[16];
		sRandom.nextBytes(byteIV);

		return new IvParameterSpec(byteIV);
	}

	// public methods
	public byte[] encrypt(byte[] plainText) throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		this.cipher.init(Cipher.ENCRYPT_MODE, this.key, this.IV, this.sRandom);

		return this.cipher.doFinal(plainText);
	}

	public byte[] decrypt(byte[] cipherText) throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
		this.cipher.init(Cipher.DECRYPT_MODE, this.key, this.IV);

		return this.cipher.doFinal(cipherText);
	}
}
