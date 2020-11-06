package me.theredcat.advancedbungeelogin;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordUtils {

    private static final Random random = new SecureRandom();
    private static final int ITERATIONS = 10000;
    private static final int KEY_LENGTH = 256;

    public static String getSalt(int length) {
        byte[] bytes = new byte[length];

        random.nextBytes(bytes);

        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] hash(char[] password, String salt) {
        PBEKeySpec spec = new PBEKeySpec(password, Base64.getDecoder().decode(salt), ITERATIONS, KEY_LENGTH);
        Arrays.fill(password, Character.MIN_VALUE);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new AssertionError("Error while hashing a password: " + e.getMessage(), e);
        } finally {
            spec.clearPassword();
        }
    }

    public static String generateSecurePassword(String password, String salt) {
        return Base64.getEncoder().encodeToString(hash(password.toCharArray(), salt));
    }

    public static boolean verifyUserPassword(String providedPassword, String securedPassword, String salt) {
        String newSecurePassword = generateSecurePassword(providedPassword, salt);

        return newSecurePassword.equalsIgnoreCase(securedPassword);
    }

}
