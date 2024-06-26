import java.math.BigInteger;
import java.util.Scanner;

public class RSA {
    public static void main(String args[]) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Enter the message to be encrypted:");
        BigInteger msg = scanner.nextBigInteger();

        System.out.println("Enter the first prime number (p):");
        BigInteger p = scanner.nextBigInteger();

        System.out.println("Enter the second prime number (q):");
        BigInteger q = scanner.nextBigInteger();

        BigInteger n = p.multiply(q);
        BigInteger z = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        System.out.println("the value of z = " + z);

        BigInteger d = BigInteger.valueOf(2);
        while (d.compareTo(z) < 0) {
            if (gcd(d, z).equals(BigInteger.ONE)) {
                break;
            }
            d = d.add(BigInteger.ONE);
        }
        System.out.println("the value of d = " + d);

        BigInteger e = BigInteger.ZERO;
        for (int i = 0; i <= 9; i++) {
            BigInteger x = BigInteger.ONE.add(BigInteger.valueOf(i).multiply(z));
            if (x.mod(d).equals(BigInteger.ZERO)) {
                e = x.divide(d);
                break;
            }
        }
        System.out.println("the value of e = " + e);

        BigInteger c = msg.modPow(e, n);
        System.out.println("Encrypted message is : " + c);

        BigInteger msgBack = c.modPow(d, n);
        System.out.println("Decrypted message is : " + msgBack);

        scanner.close();
    }

    static BigInteger gcd(BigInteger e, BigInteger z) {
        if (e.equals(BigInteger.ZERO))
            return z;
        else
            return gcd(z.mod(e), e);
    }
}
