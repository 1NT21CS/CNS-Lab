import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class SHA {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        // Ask user to input the message
        System.out.print("Enter the message to hash: ");
        String text = scanner.nextLine();
        
        scanner.close();
        
        try {
            // Create MessageDigest instance for SHA-512
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            
            // Update message digest with input text
            md.update(text.getBytes());
            
            // Get the hash's bytes
            byte[] bytes = md.digest();
            
            // Convert bytes to hexadecimal format
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            
            // Print the hash
            System.out.println("SHA-512 Hash: " + sb.toString());
        } catch (NoSuchAlgorithmException e) {
            System.err.println("SHA-512 algorithm not found");
            e.printStackTrace();
        }
    }
}
