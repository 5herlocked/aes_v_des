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

1. Split up plaintext input into bytes -- partitionBytes()
2. Create a byte array keyArray to be used as a key -- genKeyArray()
3. Create a byte array ivArray to be used as an initialization vector (IV) -- genIvArray()
4. Create a new SecretKeySpec w/ key array -- genSecretKeySpec();
5. Create a new IvParameterSpec using IV array -- genIvParameterSpec();
6. Create a new Cipher for DES+CBC with PKCS7 padding -- createCipher()
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
	private final int keyLength; // bits
	private final int rounds;
	private SecretKeySpec keyArray;
	private IvParameterSpec ivArray;
	Cipher cipher;

	// constructor that sets the key length + # of rounds
	public DES(){
		this.keyLength = 64; // bits
		this.rounds = 16;
	}

	// step 1.
	public void partitionBytes(String plainText){
		byte[] bytes = plainText.getBytes();
	}

	// step 2.
	public void genKeyArray(){
		// TODO: auto-generate keyBytes[], or at least change values
		byte[] keyArray = new byte[]{0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};
	}

	// step 3.
	public void genIvArray(){
		// TODO: auto-generate ivBytes[], or at least change values
		byte[] ivArray = new byte[]{0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
	}

	// step 4.
	public void genSecretKeySpec(){

	}

	// step 5.
	public void genIvParameterSpec(){

	}

	// step 6.
	public void createCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
		cipher = Cipher.getInstance("DES/ECB/PKCS7Padding");
	}

	// step 7. + 8.
	public void encrypt(){

	}

	// step 9. + 10.
	public void decrypt(){

	}

}
