import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Final {
	public static void main (String[] args) {
		// convert plaintext.txt to String
		String plainText = convertFileToString(plaintext); // input .txt file name

		// testing AES()
		// testAES();

		// testingDES()
		testDES();

	}

	// read a file as String
	public static String convertFileToString(String fileName) throws FileNotFoundException {
		//URL path = Final.class.getResource(fileName + ".txt");
		URL path = Final.class.getResource("plaintext.txt"); // TODO: Try the one above too
		//File file = new File(path.getFile());
		//BufferedReader reader = new BufferedReader(new FileReader(file));
		try {
			String res = Files.readString(Paths.get(String.valueOf(path)));
		} catch (IOException e) {
			e.printStackTrace();
		}
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
