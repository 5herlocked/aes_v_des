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
	public static void main (String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException,
		ShortBufferException, IllegalBlockSizeException, NoSuchAlgorithmException,
		BadPaddingException, InvalidKeyException {
		// convert plaintext.txt to String
		String plainText = "";
		try {
			plainText = convertFileToString("plainText.txt"); //
		} catch (IOException e){
			System.out.println("There was an issue finding the plaintext file");
			e.printStackTrace();
		}

		//TODO: Have AES generate an encryptedText file and decryptedText file to match DES
		testAES(plainText); // testing AES()

		testDES(plainText); // testingDES()

	}

	private static String convertFileToString (String path) throws IOException {

		String generatedPath = Paths.get("").toAbsolutePath() + "\\" + path;
		System.out.println(generatedPath);

		return Files.readString(Paths.get(generatedPath));
	}

	private static void testAES(String plainText) {
		byte[] stringBuffer = plainText.getBytes(StandardCharsets.UTF_8);
		byte[] encryptedBuffer = stringBuffer.clone();
		byte[] decryptedBuffer = stringBuffer.clone();

		long startTime = System.nanoTime(), endTime = -1;

		// Initialises AES 128
		AES aesCBC = null;
		try {
			aesCBC = new AES(128);

			encryptedBuffer = aesCBC.encrypt(stringBuffer);
			decryptedBuffer = aesCBC.decrypt(encryptedBuffer);

			endTime = System.nanoTime();
		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("AES-128 encryption and decryption time taken: "
			+ getTime(startTime, endTime) + " (ms)");

		try {
			writeToFile("encrypted_AES.txt", encryptedBuffer);
		} catch (IOException e) {
			System.out.println("Could not write encrypted output to new file encrypted_AES.txt");
		}

		try {
			writeToFile("decrypted_AES.txt", decryptedBuffer);
		} catch (IOException e) {
			System.out.println("Could not write decrypted output to new file decrypted_AES.txt");
		}
	}

	private static void writeToFile (String s, byte[] decryptedBuffer) throws IOException {
		FileOutputStream writeStream = new FileOutputStream(s);
		writeStream.write(decryptedBuffer);
		writeStream.close();
	}

	public static void testDES(String plainText) {
		byte[] stringBuffer = plainText.getBytes(StandardCharsets.UTF_8);
		byte[] encryptedBuffer = stringBuffer.clone();
		byte[] decryptedBuffer = stringBuffer.clone();

		long startTime = System.nanoTime(), endTime = -1;

		DES desCBC = null;
		try {
			desCBC = new DES();
			encryptedBuffer = desCBC.encrypt(stringBuffer);
			decryptedBuffer = desCBC.decrypt(encryptedBuffer);
			endTime = System.nanoTime();
		} catch (Exception ignored) {

		}

		long duration = getTime(startTime, endTime);
		System.out.println("DES encryption and decryption time taken: " + duration + " (ms)");

		try {
			writeToFile("encrypted_DES.txt", encryptedBuffer);
		} catch (IOException e){
			System.out.println("Could not write encrypted output to new file encrypted.dat");
		}
		try {
			writeToFile("decrypted_DES.txt", decryptedBuffer);
		} catch (IOException e){
			System.out.println("Could not write decrypted output to new file decrypted.dat");
		}
	}


	private static long getTime(long startTime, long endTime) {
		//divide by 1000000 for ms
		return (endTime - startTime) / 1000000;
	}
}
