import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Final {
	final static String filename = "plaintext5.txt";

	public static void main (String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException,
		ShortBufferException, IllegalBlockSizeException, NoSuchAlgorithmException,
		BadPaddingException, InvalidKeyException {
		// convert plaintext1.txt to String
		String plainText = "";
		try {
			plainText = convertFileToString(); //
		} catch (IOException e){
			System.out.println("There was an issue finding the plaintext file");
			e.printStackTrace();
		}

//		// AES 128 testing
//		AES aes_128 = new AES(128);
//		// change this on the day of the presentation for the various modes
//		long sumCounter = 0;
//		for (int j = 0; j < 1000; j++) {
//			sumCounter += testAES(aes_128, plainText); // testing AES()
//		}
//
//		System.out.println("AES-128 average runtime: " + sumCounter/1000 + " ns");
//
//
//		// AES 192 testing
//		AES aes_192 = new AES(192);
//		// change this on the day of the presentation for the various modes
//		sumCounter = 0;
//		for (int j = 0; j < 1000; j++) {
//			sumCounter += testAES(aes_192, plainText); // testing AES()
//		}
//
//		System.out.println("AES-192 average runtime: " + sumCounter/1000 + " ns");
//
//
//		// AES 256 testing
//		AES aes_256 = new AES(256);
//		// change this on the day of the presentation for the various modes
//		sumCounter = 0;
//		for (int j = 0; j < 1000; j++) {
//			sumCounter += testAES(aes_256, plainText); // testing AES()
//		}
//
//		System.out.println("AES-256 average runtime: " + sumCounter/1000 + " ns");


		// DES testing
		DES des = new DES();

		long sumCounter = 0;
		for (int j = 0; j < 1000; j++) {
			sumCounter += testDES(des, plainText); // testing DES
		}

		System.out.println("DES average runtime: " + sumCounter/1000 + " ns");

	}

	private static String convertFileToString () throws IOException {

		String generatedPath = Paths.get("").toAbsolutePath() + "\\" + Final.filename;
		System.out.println(generatedPath);

		return Files.readString(Paths.get(generatedPath));
	}

	private static long testAES(AES instance, String plainText) {
		byte[] stringBuffer = plainText.getBytes(StandardCharsets.UTF_8);
		byte[] encryptedBuffer = stringBuffer.clone();
		byte[] decryptedBuffer = stringBuffer.clone();

		long startTime = System.nanoTime(), endTime = -1;

		// Initialises AES
		try {
			encryptedBuffer = instance.encrypt(stringBuffer);
			decryptedBuffer = instance.decrypt(encryptedBuffer);

			endTime = System.nanoTime();
		} catch (Exception e) {
			e.printStackTrace();
		}

		long duration = getTime(startTime, endTime);

//		System.out.println("AES-128 encryption and decryption time taken: "
//			+ duration + " (ms)");
//
//		try {
//			writeToFile("encrypted_AES.txt", encryptedBuffer);
//		} catch (IOException e) {
//			System.out.println("Could not write encrypted output to new file encrypted_AES.txt");
//		}
//
//		try {
//			writeToFile("decrypted_AES.txt", decryptedBuffer);
//		} catch (IOException e) {
//			System.out.println("Could not write decrypted output to new file decrypted_AES.txt");
//		}

		return duration;
	}

	private static void writeToFile (String s, byte[] decryptedBuffer) throws IOException {
		FileOutputStream writeStream = new FileOutputStream(s);
		writeStream.write(decryptedBuffer);
		writeStream.close();
	}

	public static long testDES(DES instance, String plainText) {
		byte[] stringBuffer = plainText.getBytes(StandardCharsets.UTF_8);
		byte[] encryptedBuffer = stringBuffer.clone();
		byte[] decryptedBuffer = stringBuffer.clone();

		long startTime = System.nanoTime(), endTime = -1;

		try {
			encryptedBuffer = instance.encrypt(stringBuffer);
			decryptedBuffer = instance.decrypt(encryptedBuffer);
			endTime = System.nanoTime();
		} catch (Exception ignored) {

		}

		long duration = getTime(startTime, endTime);
//		System.out.println("DES encryption and decryption time taken: " + duration + " (ns)");
//
//		try {
//			writeToFile("encrypted_DES_" + filename, encryptedBuffer);
//		} catch (IOException e){
//			System.out.println("Could not write encrypted output to new file encrypted_DES.txt");
//		}
//		try {
//			writeToFile("decrypted_DES_" + filename, decryptedBuffer);
//		} catch (IOException e){
//			System.out.println("Could not write decrypted output to new file decrypted_DES.txt");
//		}

		return duration;
	}


	private static long getTime(long startTime, long endTime) {
		return (endTime - startTime);
	}
}
