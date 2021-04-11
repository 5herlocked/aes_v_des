public class Final {
	public static void main (String[] args) {
<<<<<<< Updated upstream
		int keyLength = 16; // bytes
		int rounds = 10; // 10 rounds + 16 bytes = AES128
=======
		// convert plaintext.txt to String
		String plainText = null; //
		try {
			plainText = convertFileToString();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		System.out.println(plainText);

		// testing AES()
		// testAES();

		// testingDES()
		//testDES();

	}

	// read a file as String
	public static String convertFileToString() throws FileNotFoundException {
		String plaintext ="";
		try {
			plaintext = new String(Files.readAllBytes(Paths.get("plaintext.txt")));
		} catch (IOException e){
			e.printStackTrace();
		}
		return plaintext;
	}

	public static void testAES(){
		int keyLength = 128; // bytes defining AES 128
>>>>>>> Stashed changes
		long startTime = System.nanoTime();
		Rijndael aesTest = new Rijndael(keyLength);
		long endTime = System.nanoTime();
		long duration = (endTime - startTime) / 1000000; //divide by 1000000 for ms

	}
}
