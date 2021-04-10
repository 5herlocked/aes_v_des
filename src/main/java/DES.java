import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.charset.*;
import java.security.*;

/*
-- Main Idea --
Takes a 64-bit plaintext and a 64-bit key
Uses a different 48-bit sub-key in each of the 16 rounds derived from the main key
Generates a 64-bit ciphertext
*/

/*
-- Key Derivation --
Compress the given 64-bit key into 48-bit keys using a 56-bit table
 */

public class DES {
	private final int keyLength; // bits
	private final int rounds;
	private SecretKey generatedKey;
	Cipher cipher;

	public DES(String plainText){
		this.keyLength = 64; // bits
		this.rounds = 16;
	}

	public void generateKey() throws NoSuchAlgorithmException, NoSuchPaddingException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
		keyGenerator.init(keyLength);
		this.generatedKey = keyGenerator.generateKey();
		cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
	}

	public void encrypt(){

	}
}
