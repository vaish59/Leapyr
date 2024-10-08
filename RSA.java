import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

public class RSA {

    private BigInteger p, q, n, phi, e, d;
    private int bitLength = 1024; // Size of the prime numbers

    // Constructor to generate the public and private keys
    public RSA() {
        Random rand = new Random();
        p = BigInteger.probablePrime(bitLength, rand);
        q = BigInteger.probablePrime(bitLength, rand);
        n = p.multiply(q); // n = p * q
        phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE)); // phi = (p-1)(q-1)

        e = BigInteger.probablePrime(bitLength / 2, rand); // Generate public key exponent e
        while (phi.gcd(e).intValue() > 1) {
            e = BigInteger.probablePrime(bitLength / 2, rand);
        }
        d = e.modInverse(phi); // Calculate private key exponent d
    }

    // Encryption
    public BigInteger[] encrypt(String message) {
        byte[] bytes = message.getBytes();
        BigInteger[] encrypted = new BigInteger[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            encrypted[i] = BigInteger.valueOf(bytes[i]).modPow(e, n);
        }
        return encrypted;
    }

    // Decryption
    public String decrypt(BigInteger[] encrypted) {
        byte[] decrypted = new byte[encrypted.length];
        for (int i = 0; i < encrypted.length; i++) {
            decrypted[i] = (encrypted[i].modPow(d, n)).byteValue();
        }
        return new String(decrypted);
    }

    // Main driver code
    public static void main(String[] args) {
        RSA rsa = new RSA();
        Scanner scanner = new Scanner(System.in);

        System.out.println("Public Key (e, n): (" + rsa.e + ", " + rsa.n + ")");
        System.out.println("Private Key (d, n): (" + rsa.d + ", " + rsa.n + ")");

        System.out.print("Enter a message to encrypt: ");
        String message = scanner.nextLine();

        BigInteger[] encryptedMessage = rsa.encrypt(message);
        System.out.println("Encrypted message: ");
        for (BigInteger val : encryptedMessage) {
            System.out.print(val + " ");
        }

        System.out.println("\nDecrypted message: " + rsa.decrypt(encryptedMessage));
        scanner.close();
    }
}
