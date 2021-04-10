public class Final {
	public static void main (String[] args) {
		int keyLength = 16; // bytes
		int rounds = 10; // 10 rounds + 16 bytes = AES128
		long startTime = System.nanoTime();
		Rijndael aesTest = new Rijndael(keyLength, rounds);
		long endTime = System.nanoTime();
		long duration = (endTime - startTime) / 1000000; //divide by 1000000 for ms

	}
}
