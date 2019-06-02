package sample;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

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

    FileEncrypterDecrypter(String transformtion) throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.cipher = Cipher.getInstance(transformtion);
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

    public void decryptSessionKey(PrivateKey privateKey, RSA RSADecrypter) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        /*InputStream is = new FileInputStream("C:\\Users\\Win10\\Desktop\\IT\\keySession");
        BufferedReader buf = new BufferedReader(new InputStreamReader(is));
        String line = buf.readLine();
        StringBuilder sb = new StringBuilder();
        while(line != null){
            sb.append(line);
            line = buf.readLine();
        }*/
        //String sb = new String(Files.readAllBytes(Paths.get("C:\\Users\\Win10\\Desktop\\IT\\keySession")));
        //sb = sb.replaceAll("\\r\\n","");

        //sb->encrypted session key

        InputStream is2 = new FileInputStream("C:\\Users\\Win10\\Desktop\\IT\\keySession");
        BufferedReader buf2 = new BufferedReader(new InputStreamReader(is2));
        String line2 = buf2.readLine();
        StringBuilder sb2 = new StringBuilder();
        while(line2 != null){
            sb2.append(line2).append("\n");
            line2 = buf2.readLine();
        }

        //String sb2 = new String(Files.readAllBytes(Paths.get("C:\\Users\\Win10\\IdeaProjects\\AES\\privateKeys.txt")));
        //sb2.replaceAll("\\r\\n","");

        /*KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec specPriv = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(sb2.trim()));
        PrivateKey privKey = kf.generatePrivate(specPriv);*/


        //String keySession = RSAdecryoter.decrypt(sb,privKey);
        String keySession = RSADecrypter.decrypt(sb2.toString(),privateKey);

        byte[] decodedSessionKey = Base64.getDecoder().decode(keySession.trim());
        System.out.println("Decoded session key: "+decodedSessionKey.toString());
        //byte[] decodedSessionKey = Base64.getDecoder().decode(sb.trim());
        this.secretKey = new SecretKeySpec(decodedSessionKey, 0,
                decodedSessionKey.length, "AES");

        /*byte[] decodedKey = Base64.getDecoder().decode(sb.toString());
        SecretKey secretKey = new SecretKeySpec(decodedKey, 0,
                decodedKey.length, "RSA");*/
    }

    public void decryptFile(File f, String mode)
            throws Exception {

        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        System.out.println("Decrypting file: " + f.getName());
        try {
            if(mode.equals("ECB")){
                this.cipher.init(Cipher.DECRYPT_MODE, this.secretKey );
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
