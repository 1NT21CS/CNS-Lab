import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class AES {

    private SecretKeySpec secretKeySpec;

    public AES(String secretKey) {
        this.secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "AES");
    }

    public String encrypt(String text) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            byte[] encryptedBytes = cipher.doFinal(text.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            System.err.println("Encryption Error: " + e.getMessage());
            return null;
        }
    }

    public String decrypt(String encryptedText) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            return new String(decryptedBytes);
        } catch (Exception e) {
            System.err.println("Decryption Error: " + e.getMessage());
            return null;
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter a secret key (16, 24, or 32 characters): ");
        String secretKey = scanner.nextLine();

        System.out.print("Enter the text to encrypt: ");
        String textToEncrypt = scanner.nextLine();

        AES aes = new AES(secretKey);

        String encryptedText = aes.encrypt(textToEncrypt);
        if (encryptedText != null) {
            System.out.println("\nEncrypted Text: " + encryptedText);

            String decryptedText = aes.decrypt(encryptedText);
            if (decryptedText != null) {
                System.out.println("Decrypted Text: " + decryptedText);
            }
        }

        scanner.close();
    }
}
