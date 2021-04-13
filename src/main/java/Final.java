import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Final {
	public static void main (String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, ShortBufferException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
		// convert plaintext.txt to String
//		String plainText = "";
//		try {
//			plainText = convertFileToString(); //
//		} catch (IOException e){
//			System.out.println("There was an issue finding the plaintext file");
//			e.printStackTrace();
//		}

		//TODO: Have AES generate an encryptedText file and decryptedText file to match DES
		testAES("6bc1bee22e409f96e93d7e117393172a" +
			"ae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411e5fbc1191a0a52ef" +
			"f69f2445df4f9b17ad2b417be66c3710"); // testing AES()

		//TODO: Don't read DES from a file, store the file into the code itself to not rely on OS times
		//testDES(plainText); // testingDES()

	}

	private static String convertFileToString (String path) throws IOException {
		return "";
	}

	private static void testAES(String plainText) {
		byte[] stringBuffer = plainText.getBytes(StandardCharsets.UTF_8);
		byte[] encryptedBuffer = stringBuffer;
		byte[] decryptedBuffer = stringBuffer;
		System.out.println("Plaintext: " + plainText);

		long startTime = System.nanoTime(), endTime = -1;

		// Initialises AES 128
		Rijndael aesCBC = null;
		try {
			aesCBC = new Rijndael(128);

			aesCBC.encrypt(encryptedBuffer);
			aesCBC.decrypt(decryptedBuffer);

			endTime = System.nanoTime();
		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("CipherText: " + Arrays.toString(encryptedBuffer));
		System.out.println("Plaintext decrypted from ciphertext: " + Arrays.toString(decryptedBuffer));

		if (Arrays.equals(stringBuffer, plainText.getBytes(StandardCharsets.UTF_8)) && endTime != -1) {
			System.out.println("AES CBC Encryption and Decryption successful");

			System.out.println("Time taken: " + getTime(startTime, endTime));
		}
		else {
			System.out.println("AES CBC Encryption and Decryption unsuccessful.");
			System.out.println("Time lapsed: " + getTime(startTime, endTime));
		}
	}

	public static void testDES(String plainText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		long startTime = System.nanoTime();
		DES desCBC = new DES(plainText);
		desCBC.partitionBytes();
		desCBC.genKeyArray();
		desCBC.genIvArray();
		desCBC.genSecretKeySpec();
		desCBC.genIvParameterSpec();
		desCBC.createCipher();
		desCBC.encrypt();
		try {
			desCBC.writeEncryptOutput();
		} catch (IOException e){
			System.out.println("Could not write encrypted output to new file decrypted.dat");
		}
		desCBC.decrypt();
		try {
			desCBC.writeDecryptOutput();
		} catch (IOException e){
			System.out.println("Could not write decrypted output to new file decrypted.dat");
		}
		long endTime = System.nanoTime();
		long duration = getTime(startTime, endTime); //divide by 1000000 for ms
		System.out.println("DES encryption and decryption time taken: " + duration + " (ms)");
	}


	private static long getTime(long startTime, long endTime) {
		return (endTime - startTime) / 1000000;
	}
}
