import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Final {
	public static void main (String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, ShortBufferException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
		// convert plaintext.txt to String
		String plainText = "";
		try {
			plainText = convertFileToString(); //
		} catch (IOException e){
			System.out.println("There was an issue finding the plaintext file");
			e.printStackTrace();
		}

		//TODO: Have AES generate an encryptedText file and decryptedText file to match DES
		// testAES(); // testing AES()

		//TODO: Don't read DES from a file, store the file into the code itself to not rely on OS times
		testDES(plainText); // testingDES()

	}

	// read a file as String
	public static String convertFileToString() throws IOException{
		Path path = Paths.get("src/main/java/plaintext.txt");
		return Files.readString(path);
	}

	public static void testAES(){
		int keyLength = 16; // bytes
		int rounds = 10; // 10 rounds + 16 bytes = AES128
		long startTime = System.nanoTime();
		Rijndael aesTest = new Rijndael(keyLength, rounds);
		long endTime = System.nanoTime();
		long duration = (endTime - startTime) / 1000000; //divide by 1000000 for ms
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
		long duration = (endTime - startTime) / 1000000; //divide by 1000000 for ms
		System.out.println("DES encryption and decryption time taken: " + duration + " (ms)");
	}
}
