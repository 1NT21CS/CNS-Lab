//Code should be in C language according to the question in syllabus (5. Write a C program to implement DES algorithm.)
//DES ALGORITHM

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Scanner;

public class DESAlgorithm {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter the plaintext: ");
        String plaintext = scanner.nextLine();

        System.out.print("Enter the encryption key (8 characters): ");
        String key = scanner.nextLine();

        byte[] encrypted = encrypt(plaintext, key);
        System.out.println("Encrypted: " + new String(encrypted));

        String decrypted = decrypt(encrypted, key);
        System.out.println("Decrypted: " + decrypted);

        scanner.close();
    }

    public static byte[] encrypt(String plaintext, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "DES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plaintext.getBytes());
    }

    public static String decrypt(byte[] ciphertext, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "DES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes);
    }
}
