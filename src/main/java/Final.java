import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Final {
	public static void main (String[] args) {
		// convert plaintext.txt to String
		try {
			String plainText = convertFileToString(); //
			System.out.println(plainText);
		} catch (IOException e){
			System.out.println("There was an issue finding the plaintext file");
			e.printStackTrace();
		}



		// testing AES()
		// testAES();

		// testingDES()
		//testDES();

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

	public static void testDES(String plainText){
		// TODO
	}
}
