import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Final {
	public static void main (String[] args) {
		// convert plaintext.txt to String
		String plainText = convertFileToString(); //
		System.out.println(plainText);

		// testing AES()
		// testAES();

		// testingDES()
		//testDES();

	}

	// read a file as String
	public static String convertFileToString(){
		String plaintext ="";
		try {
			plaintext = new String(Files.readAllBytes(Paths.get("plaintext.txt")));
		} catch (IOException e){
			e.printStackTrace();
		}
		return plaintext;
	}

	public static void testAES(){
		int keyLength = 16; // bytes
		int rounds = 10; // 10 rounds + 16 bytes = AES128
		long startTime = System.nanoTime();
		Rijndael aesTest = new Rijndael(keyLength, rounds);
		long endTime = System.nanoTime();
		long duration = (endTime - startTime) / 1000000; //divide by 1000000 for ms
	}

	public static void testDES(String plainText){
		// TODO
	}
}
