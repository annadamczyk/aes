package sample;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public class FileEncrypterDecrypter {
    public SecretKey secretKey;
    public Cipher cipher;

    FileEncrypterDecrypter(SecretKey secretKey, String transformation) throws Exception{
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
        byte[] output = this.cipher.doFinal(input); //bajty pliku

        out.write(output);

        out.flush();
        out.close();
        in.close();
    }

    public void sendFile(File f, Socket socket) throws Exception{
        FileInputStream in = new FileInputStream(f);
        byte[] input = new byte[(int) f.length()];
        in.read(input);

        FileOutputStream out = new FileOutputStream(f);
        byte[] output = this.cipher.doFinal(input); //bajty pliku

        OutputStream outputStream = socket.getOutputStream();
        outputStream.write(output);
        outputStream.flush();
    }

    public  void saveFile(File f, Socket socket) throws Exception{
        InputStream input = socket.getInputStream();
        FileOutputStream fileOutputStream = new FileOutputStream(f);
        byte[] bytes = new byte[(int)f.length()];
        input.read(bytes,0, bytes.length);
        fileOutputStream.write(bytes,0,bytes.length);
    }

    public void encryptFile(File f, String mode, Socket socket)
            throws Exception {
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
        this.sendFile(f, socket);
        //this.writeToFile(f);
    }

    public void decryptFile(File f, String mode)
            throws Exception {
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
        //this.sendFile(f);
        this.writeToFile(f);
    }
}
