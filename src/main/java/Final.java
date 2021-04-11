import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
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

		// testing AES()
		// testAES();

		// testingDES()
		testDES(plainText);

	}

	// read a file as String
	public static String convertFileToString() throws IOException{
		Path path = Paths.get("src/main/java/plaintext.txt");
		String res = Files.readString(path);
		return res;
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
		// TODO
		int keyLength = 16; // bytes
		int rounds = 10; // 10 rounds + 16 bytes = AES128
		long startTime = System.nanoTime();
		DES desCBC = new DES(plainText);
		desCBC.partitionBytes();
		desCBC.genKeyArray();
		desCBC.genIvArray();
		desCBC.genSecretKeySpec();
		desCBC.genIvParameterSpec();
		desCBC.createCipher();
		desCBC.encrypt();
		desCBC.decrypt();
		long endTime = System.nanoTime();
		long duration = (endTime - startTime) / 1000000; //divide by 1000000 for ms
		System.out.println("DES encryption and decryption time taken: " + duration + " (ms)");
	}
}
