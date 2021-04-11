import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.charset.*;
import java.security.*;

/*
-- Main Idea --
>> DES using CBC with padding <<
Takes a 64-bit plaintext
using a 64-bit cipher key + 64-bit IV
Outputs a 64-bit plaintext

1. Split up plaintext input into bytes array inputBytes[] -- partitionBytes()
2. Create a byte array keyArray to be used as a key -- genKeyArray()
3. Create a byte array ivArray to be used as an initialization vector (IV) -- genIvArray()
4. Create a new SecretKeySpec secretKeySpec w/ key array -- genSecretKeySpec();
5. Create a new IvParameterSpec ivParameterSpec using IV array -- genIvParameterSpec();
6. Create a new Cipher for DES+CBC with PKCS5 padding -- createCipher()
7. Init Cipher to encryption mode using key array + iv array
8. Encrypt w/ help of Cipher API -- encrypt()
9. Init Cipher to decryption mode
10. Decrypt -- decrypt()
*/

/*
-- Key Derivation --
Compress the given 64-bit key into 48-bit keys using a 56-bit table
 */

public class DES {
	private String plainText;
	private final int keyLength; // bits
	private final int rounds;
	private int cipherTextLength;
	private int decryptedTextLength;
	private byte[] inputBytes;
	private byte[] keyArray;
	private byte[] ivArray;
	private byte[] encryptedBytes;
	private byte[] decryptedBytes;
	private SecretKeySpec secretKeySpec;
	private IvParameterSpec ivParameterSpec;
	Cipher cipher;

	// constructor that sets the key length + # of rounds
	public DES(String plainText){
		this.keyLength = 64; // bits
		this.rounds = 16;
		this.plainText = plainText;
	}

	// step 1.
	public void partitionBytes(){
		byte[] inputBytes = plainText.getBytes();
	}

	// step 2.
	public void genKeyArray(){
		// TODO: auto-generate keyBytes[], or at least change values
		keyArray = new byte[]{0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};
	}

	// step 3.
	public void genIvArray(){
		// TODO: auto-generate ivBytes[], or at least change values
		ivArray = new byte[]{0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
	}

	// step 4.
	public void genSecretKeySpec(){
		secretKeySpec = new SecretKeySpec(keyArray, "DES");
	}

	// step 5.
	public void genIvParameterSpec(){
		ivParameterSpec = new IvParameterSpec(ivArray);
	}

	// step 6.
	public void createCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
		cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
	}

	public void encrypt() throws InvalidAlgorithmParameterException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		// step 7.
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
		// step 8.
		encryptedBytes = new byte[cipher.getOutputSize(inputBytes.length)];
		cipherTextLength = cipher.update(inputBytes, 0, inputBytes.length, encryptedBytes, 0);
		cipherTextLength += cipher.doFinal(encryptedBytes, cipherTextLength);
	}

	public void decrypt() throws InvalidAlgorithmParameterException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		// step 9.
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
		// step 10.
		decryptedTextLength = cipher.update(encryptedBytes, 0, cipherTextLength, decryptedBytes, 0);
		decryptedTextLength += cipher.doFinal(decryptedBytes, decryptedTextLength);
	}

}
