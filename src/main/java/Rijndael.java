import javax.crypto.*;
import java.security.*;

/*
-- Main Idea --
>> AES using CBC with padding <<
Takes a 128-bit block plaintext
using a x-bit cipher key + x-bit IV
Outputs a 128-bit block ciphertext
1. Derive round keys using AES key schedule. AES requires separate 128-bit round key block for each round
2. Initial AddRoundKey: each byte of the state is combined with a byte of the round key using XOR
3. 9, 11, 13 rounds (as necessary):
	i. SubBytes - nonlinear substitution step
	ii. ShiftRows - transposition step where the last three rows of a the state are shifted cyclically a certain number
		of steps
	iii. MixColumns - a linear mixing operation which operates on the columns of the state, combining the four bytes
		in each column
	iv. AddRoundKey
4. Final Round:
	i. SubBytes
	ii. ShiftRows
	iii. AddRoundKey
*/

public class Rijndael {

	// Static Variables
	private static final int[] sBox = {
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
	};

	private static final int[] rSBox = {
		0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
		0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
		0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
		0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
		0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
		0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
		0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
		0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
		0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
		0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
		0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
		0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
		0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
		0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
		0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
	};

	private static final int[] rCon = {
		0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
	};


	// Instance Variables

	// temporary 4 x 4 storage for intermediate results
	private byte[][] state = new byte[4][4];

	// instance storage for the IV
	private byte[] initialiseVector;

	// number of columns defining a state in AES. It is constant
	private static final int numCol = 4;

	private int keyLength;

	private final int rounds;

	private SecretKey generatedKey;

	private byte[][] roundKeys;

	// Constructor

	// Receives the length of the key and deduces the version of AES being used
	// Defaults to AES 128/ 10 rounds
	public Rijndael (int keyLength) {
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
	}

	// Private Methods
	private void generateIV () throws Exception {
		byte[] IV = new byte[16];
		SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
		prng.nextBytes(IV);

		this.initialiseVector = IV;
	}


	// This shifts the 4 bytes in a word to the left once.
	private void rotWord (byte[] word) {
		byte temp = word[0];
		word[0] = word[1];
		word[2] = word[3];
		word[3] = temp;
	}

	// SubWord takes a four byte input word and applies S-box to each byte
	private void subWord (byte[] word) {
		word[0] = (byte) sBox[word[0]];
		word[1] = (byte) sBox[word[1]];
		word[2] = (byte) sBox[word[2]];
		word[3] = (byte) sBox[word[3]];
	}

	// This function produces Round + 1 number of round keys
	private void keyExpansion (byte[] roundKey) {

		byte[] temp = new byte[4];

		int a, b, c; // temp variables

		// First round of key expansions
		for (int i = 0; i < rounds; i++) {
			roundKey[(i * 4) + 0] = generatedKey.getEncoded()[(i * 4) + 0];
			roundKey[(i * 4) + 1] = generatedKey.getEncoded()[(i * 4) + 1];
			roundKey[(i * 4) + 2] = generatedKey.getEncoded()[(i * 4) + 2];
			roundKey[(i * 4) + 3] = generatedKey.getEncoded()[(i * 4) + 3];
		}

		// All other round keys are found from the previous round keys.
		for (int i = rounds; i < numCol * (rounds + 1); i++) {
			c = ((i - 1) * 4);

			temp[0] = roundKey[c + 0];
			temp[0] = roundKey[c + 1];
			temp[0] = roundKey[c + 2];
			temp[0] = roundKey[c + 3];

			if (i % numCol == 0) {
				// Rotate word
				rotWord(temp);
				// and then substitute it
				subWord(temp);

				temp[0] = (byte) (temp[0] ^ rCon[i / numCol]);
			}

			if (this.keyLength == 256) {
				if (i % numCol == 4) {
					subWord(temp);
				}
			}

			b = i * 4;
			c = (i - numCol) * 4;

			roundKey[b + 0] = (byte) (roundKey[c + 0] ^ temp[0]);
			roundKey[b + 1] = (byte) (roundKey[c + 1] ^ temp[1]);
			roundKey[b + 2] = (byte) (roundKey[c + 2] ^ temp[2]);
			roundKey[b + 3] = (byte) (roundKey[c + 3] ^ temp[3]);
		}

	}

	/*
		Adds the round key to the current intermediate state
	 */
	private void addRoundKey (byte round, byte[] roundKey) {
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				state[i][j] ^= roundKey[(round * numCol * 4) + (i * numCol) + j];
			}
		}
	}

	/*
		Substitutes the bytes based on the current state
	 */
	private void subBytes () {
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				state[j][i] = (byte) sBox[state[j][i]];
			}
		}
	}

	private void shiftRows () {
		byte temp;

		// Rotate first row 1 columns left
		temp = state[0][1];
		state[0][1] = state[1][1];
		state[1][1] = state[2][1];
		state[2][1] = state[3][1];
		state[3][1] = temp;

		// Rotate second row 2 columns left
		temp = state[0][2];
		state[0][2] = state[2][2];
		state[2][2] = temp;

		temp = state[1][2];
		state[1][2] = state[3][2];
		state[3][2] = temp;

		// Rotate third row 3 columns left
		temp = state[0][3];
		state[0][3] = state[3][3];
		state[3][3] = state[2][3];
		state[2][3] = state[1][3];
		state[1][3] = temp;
	}

	private void cipher (byte[] buffer, int counter) {


	}

	private void invCipher (byte[] buffer, int counter) {

	}


	// PUBLIC METHODS for AES CBC
	public void xorWithIV (byte[] buffer, byte[] Iv) {
		for (int i = 0; i < 128; i++) {
			buffer[i] ^= Iv[i];
		}
	}

	public void encrypt (byte[] buffer) {

		if (this.initialiseVector == null) {
			try {
				generateIV();
			} catch (Exception e) {
				e.printStackTrace();
				System.exit(-1);
			}
		}
		byte[] Iv = this.initialiseVector;

		for (int i = 0; i < buffer.length; i += 128) {
			xorWithIV(buffer, Iv);

			// Does the actual encryption
			cipher(buffer, i);  // Passes in the buffer and how much of it is already encrypted

			Iv = buffer;
		}

	}

	public void decrypt (byte[] buffer) {

		if (this.initialiseVector == null) {
			System.out.println("Trying to decrypt without initialising");
			return;
		}

		for (int i = 0; i < buffer.length; i += 128) {

			invCipher(buffer, i);   // Passes in the buffer and how much of it is already decrypted

			xorWithIV(buffer, this.initialiseVector);
		}

	}
}


//	public byte[] encrypt(String plainText) throws
//		InvalidAlgorithmParameterException, InvalidKeyException,
//		NoSuchAlgorithmException, NoSuchPaddingException,
//		UnsupportedEncodingException, BadPaddingException,
//		IllegalBlockSizeException {
//		byte[] clean = plainText.getBytes();
//
//		if (this.generatedKey == null) {
//			this.generateKey();
//		}
//
//		// Generating IV
//		int ivSize = 16;
//		byte[] iv = new byte[ivSize];
//		SecureRandom random = new SecureRandom();
//		random.nextBytes(iv);
//		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
//
//		// Hashing key.
//		MessageDigest digest = MessageDigest.getInstance("SHA-256");
//		digest.update(generatedKey.toString().getBytes(StandardCharsets.UTF_8));
//		byte[] keyBytes = new byte[16];
//		System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
//		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
//
//		// Encrypt.
//		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
//		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
//		byte[] encrypted = cipher.doFinal(clean);
//
//		// Combine IV and encrypted part.
//		byte[] encryptedIVAndText = new byte[ivSize + encrypted.length];
//		System.arraycopy(iv, 0, encryptedIVAndText, 0, ivSize);
//		System.arraycopy(encrypted, 0, encryptedIVAndText, ivSize, encrypted.length);
//
//		return encryptedIVAndText;
//	}
//
//	public String decrypt(byte[] encryptedIvTextBytes, String key) throws
//		NoSuchAlgorithmException, NoSuchPaddingException,
//		BadPaddingException, IllegalBlockSizeException,
//		InvalidAlgorithmParameterException, InvalidKeyException {
//		int ivSize = 16;
//		int keySize = 16;
//
//		// Extract IV.
//		byte[] iv = new byte[ivSize];
//		System.arraycopy(encryptedIvTextBytes, 0, iv, 0, iv.length);
//		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
//
//		// Extract encrypted part.
//		int encryptedSize = encryptedIvTextBytes.length - ivSize;
//		byte[] encryptedBytes = new byte[encryptedSize];
//		System.arraycopy(encryptedIvTextBytes, ivSize, encryptedBytes, 0, encryptedSize);
//
//		// Hash key.
//		byte[] keyBytes = new byte[keySize];
//		MessageDigest md = MessageDigest.getInstance("SHA-256");
//		md.update(key.getBytes());
//		System.arraycopy(md.digest(), 0, keyBytes, 0, keyBytes.length);
//		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
//
//		// Decrypt.
//		Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS7Padding");
//		cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
//		byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);
//
//		return new String(decrypted);
//	}

