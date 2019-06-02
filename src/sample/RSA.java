package sample;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSA {
    public static KeyPair generateKeyPair(int keySize) throws Exception { //key size 2048 to tests
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize, new SecureRandom());

        return generator.generateKeyPair(); //KeyPair
    }

    public static String encrypt(String sessionKey, PublicKey publicKey) throws Exception {
        Cipher encryotCipher = Cipher.getInstance("RSA");
        encryotCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryotCipher.doFinal(sessionKey.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public  static String decrypt(String cipherText, PrivateKey privateKey) {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        String decryptedSessionKey =null;
        Cipher decriptCipher = null;
        try {
            decriptCipher = Cipher.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        try {
            decriptCipher.init(Cipher.DECRYPT_MODE,privateKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        try {
            decryptedSessionKey = new String(decriptCipher.doFinal(bytes), UTF_8);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        return decryptedSessionKey;
    }
}
