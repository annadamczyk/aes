package sample;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class FileEncrypterDecrypter {
    public SecretKey secretKey;
    public Cipher cipher;

    FileEncrypterDecrypter(SecretKey secretKey, String transformation) {
        this.secretKey = secretKey;
        try {
            this.cipher = Cipher.getInstance(transformation);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    public void writeToFile(File f) throws IOException, IllegalBlockSizeException, BadPaddingException {
        FileInputStream in = new FileInputStream(f);
        byte[] input = new byte[(int) f.length()];
        in.read(input);

        FileOutputStream out = new FileOutputStream(f);
        byte[] output = this.cipher.doFinal(input);
        out.write(output);

        out.flush();
        out.close();
        in.close();
    }

    public void encryptFile(File f, String mode)
            throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        System.out.println("Encrypting file: " + f.getName());
        try {
            if(mode.equals("ECB")){
                this.cipher.init(Cipher.ENCRYPT_MODE, this.secretKey);
            }
            else if(mode.equals("CBC")) {
                this.cipher.init(Cipher.ENCRYPT_MODE, this.secretKey, ivspec);
            }
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        this.writeToFile(f);
    }

    public void decryptFile(File f, String mode)
            throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        System.out.println("Decrypting file: " + f.getName());
        try {
            if(mode.equals("ECB")){
                this.cipher.init(Cipher.DECRYPT_MODE, this.secretKey);
            }
            else if(mode.equals("CBC")) {
                this.cipher.init(Cipher.DECRYPT_MODE, this.secretKey, ivspec);
            }
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        this.writeToFile(f);
    }
}
