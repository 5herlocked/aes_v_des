import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Random;

/*
-- Main Idea --
>> DES using CBC with padding <<
Takes a 64-bit plaintext
using a 64-bit cipher key + 64-bit IV
Outputs a 64-bit plaintext

1. Split up plaintext input into bytes array inputBytes[] -- partitionBytes()
2. Create a byte array keyArray with randomly generated bytes to be used as a key -- genRandomBytes(), genKeyArray()
3. Create a byte array ivArray with randomly generated bytes to be used as an initialization vector (IV) -- genRandomBytes(), genIvArray()
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
	private byte[] keyArray;
	private byte[] ivArray;
	private SecretKeySpec secretKeySpec;
	private IvParameterSpec ivParameterSpec;
	Cipher cipher;

	// constructor that sets the key length + # of rounds
	public DES() throws NoSuchPaddingException, NoSuchAlgorithmException {
		this.genKeyArray();
		this.genIvArray();
		this.genSecretKeySpec();
		this.genIvParameterSpec();
		this.createCipher();
	}

	// step 2.
	public void genKeyArray(){
		keyArray = new byte[8];
		genRandomBytes(keyArray);
	}

	// populated input byte[] array with random bytes to use in genKeyArray() and genIVArray()
	public void genRandomBytes(byte[] bytes){
		Random r = new Random();
		r.nextBytes(bytes);
	}

	// step 3.
	public void genIvArray(){
		ivArray = new byte[8];
		 genRandomBytes(ivArray);
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
		cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
	}

	public byte[] encrypt(byte[] plainText) throws InvalidAlgorithmParameterException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException{
		// step 7.
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
		// step 8.
		return this.cipher.doFinal(plainText);
	}

	public byte[] decrypt(byte[] cipherText) throws InvalidAlgorithmParameterException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException{
		// step 9.
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
		// step 10.
		//decryptedTextLength = cipher.update(encryptedBytes, 0, cipherTextLength, decryptedBytes, 0);
		//decryptedTextLength += cipher.doFinal(decryptedBytes, decryptedTextLength);
		return this.cipher.doFinal(cipherText);
	}
}
