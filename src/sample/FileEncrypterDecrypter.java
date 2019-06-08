package sample;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
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

    public void encryptPrivateKeyCBC(PrivateKey privateKey,SecretKeySpec key,byte[] vector) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] keyBytesIv = generateVector(vector, 16);
        IvParameterSpec ivspec = new IvParameterSpec(keyBytesIv);

        //Create SecretKeySpec
        //SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

        //Create IvParameterSpec
        //IvParameterSpec ivSpec = new IvParameterSpec(ivspec);

        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);
        byte[] encodedPublicKey = privateKey.getEncoded();
        String b64PublicKey = Base64.getEncoder().encodeToString(encodedPublicKey);
        //Perform Encryption
        byte[] cipherText = cipher.doFinal(b64PublicKey.getBytes("UTF-8"));
        String ciphetT = Base64.getEncoder().encodeToString(cipherText);
        //File file = new File("C:\\Users\\Win10\\IdeaProjects\\AES\\privateKeySHA256.txt");
        //FileOutputStream fop = new FileOutputStream(file);
        //fop.write( cipherText );
        //fop.close();

        File targetFile = new File("C:\\Users\\Win10\\IdeaProjects\\AES\\privateKeySHA256.txt");
        FileOutputStream outStream = new FileOutputStream(targetFile);
        outStream.write(ciphetT.getBytes());
        outStream.flush();
        outStream.close();

        //OutputStream os = new FileOutputStream("C:\\Users\\Win10\\IdeaProjects\\AES\\privateKeySHA256.txt");
        //os.write(cipherText);
        //os.close();
    }

    static byte[] generateVector(byte[] vector, int lenght) throws UnsupportedEncodingException {
        byte[] keyBytesIv = new byte[lenght];
        int len = vector.length;

        if (len > keyBytesIv.length) {
            len = keyBytesIv.length;
        }

        System.arraycopy(vector, 0, keyBytesIv, 0, len);
        return keyBytesIv;
    }

    public void decryptPrivateKeyCBC(byte[] vector) throws Exception{
        byte[] keyBytesIv = generateVector(vector, 16);
        IvParameterSpec ivspec = new IvParameterSpec(keyBytesIv);
        //File file = new File("C:\\Users\\Win10\\IdeaProjects\\AES\\privateKeySHA256.txt");

        InputStream is2 = new FileInputStream("C:\\Users\\Win10\\IdeaProjects\\AES\\privateKeySHA256.txt");
        BufferedReader buf2 = new BufferedReader(new InputStreamReader(is2,"UTF-8"));
        String line2 = buf2.readLine();
        StringBuilder sb2 = new StringBuilder();
        while(line2 != null){
            sb2.append(line2).append("\n");
            line2 = buf2.readLine();
        }

        //Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, this.secretKey, ivspec);

        //FileInputStream in = new FileInputStream(file);
        //byte[] input = new byte[(int) file.length()];
        //in.read(input);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        while (true) {
            int r = is2.read(buffer);
            if (r == -1) break;
            out.write(buffer, 0, r);
        }

        byte[] ret = out.toByteArray();

        //FileOutputStream out = new FileOutputStream(file);
        byte[] output=null;
        try {
            //byte[] encodedPublicKey = keyPair.getPublic().getEncoded();
            byte[] b64PublicKey = Base64.getDecoder().decode(sb2.toString().trim());
            output = this.cipher.doFinal(b64PublicKey);
        }catch (Exception exc){
            System.out.println(exc.getMessage());
        }
        String s = new String(output);
        System.out.println("Private key CBC: "+s.trim());

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
            else if(mode.equals("CFB")) {
                this.cipher.init(Cipher.ENCRYPT_MODE, this.secretKey, ivspec);
            }
            else if(mode.equals("OFB")) {
                this.cipher.init(Cipher.ENCRYPT_MODE, this.secretKey, ivspec);
            }
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        this.sendFile(f, socket);
    }

    public void decryptSessionKey(PrivateKey privateKey, RSA RSADecrypter) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        InputStream is2 = new FileInputStream("C:\\Users\\Win10\\Desktop\\IT\\keySession");
        BufferedReader buf2 = new BufferedReader(new InputStreamReader(is2));
        String line2 = buf2.readLine();
        StringBuilder sb2 = new StringBuilder();
        while(line2 != null){
            sb2.append(line2).append("\n");
            line2 = buf2.readLine();
        }

        String keySession = RSADecrypter.decrypt(sb2.toString(),privateKey);
        byte[] decodedSessionKey = Base64.getDecoder().decode(keySession.trim());
        System.out.println("Decoded session key: "+decodedSessionKey.toString());
        //byte[] decodedSessionKey = Base64.getDecoder().decode(sb.trim());
        this.secretKey = new SecretKeySpec(decodedSessionKey, 0,
                decodedSessionKey.length, "AES");
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
            else if(mode.equals("CFB")){
                this.cipher.init(Cipher.DECRYPT_MODE,this.secretKey, ivspec);
            }
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        this.writeToFile(f);
    }
}
