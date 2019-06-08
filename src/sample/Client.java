package sample;

import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Pane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Client extends Application {
    private static Socket socket;
    public static void main(String[] args) throws IOException {
        socket = new Socket("localhost",4999);
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws Exception  {
        primaryStage.setTitle("Client");
        final FileChooser fileChooser = new FileChooser();
        final Button openButton = new Button("decoding...");
        final Button openButton2 = new Button("potwierdź");
        TextField textField = new TextField();

        //generate public and private keys for client
        RSA RSAEncrypter = new RSA();
        KeyPair keyPair = RSAEncrypter.generateKeyPair(512);

        byte[] encodedPublicKey = keyPair.getPublic().getEncoded();
        String b64PublicKey = Base64.getEncoder().encodeToString(encodedPublicKey);
        System.out.println(b64PublicKey);
        byte[] encodedPrivateKey1 = keyPair.getPrivate().getEncoded();
        String b64PublicKey1 = Base64.getEncoder().encodeToString(encodedPrivateKey1);
        System.out.println("private key rsa: "+b64PublicKey1);
        File file = new File("C:\\Users\\Win10\\IdeaProjects\\AES\\publicKeys.txt");
        FileOutputStream fop = new FileOutputStream(file);
        fop.write( b64PublicKey.getBytes() );
        fop.close();
        ObjectOutputStream oos = null;
        oos = new ObjectOutputStream(socket.getOutputStream());
        oos.writeObject("key");
        //save private key
        this.encryptPrivateKey(keyPair.getPrivate(), "password");
        this.decryptPrivateKey("password");

        //CFB
        final String modeHash = "CFB";
        final String mode = "AES/CFB/PKCS5PADDING";

        String finalModeHash = modeHash;
        openButton2.setOnAction(
                new EventHandler<ActionEvent>() {
                    @Override
                    public void handle(ActionEvent event) {
                        //File file = fileChooser.showOpenDialog(primaryStage);
                       // if (file != null) {

                            try {
                                InputStream input = socket.getInputStream();
                                byte[] buffer = new byte[input.available()];
                                input.read(buffer);

                                File targetFile = new File("C:\\Users\\Win10\\Desktop\\IT\\keySession");
                                OutputStream outStream = new FileOutputStream(targetFile);
                                outStream.write(buffer);
                                /*InputStream input = socket.getInputStream();

                                StringBuilder textBuilder = new StringBuilder();
                                try (Reader reader = new BufferedReader(new InputStreamReader
                                        (input, Charset.forName(StandardCharsets.UTF_8.name())))) {
                                    int c = 0;
                                    while ((c = reader.read()) != -1) {
                                        textBuilder.append((char) c);
                                    }
                                }
                                textField.setText(textBuilder.toString());*/
                            } catch (Exception e) {
                                e.printStackTrace();
                            }

                        //}
                    }
                });

        openButton.setOnAction( //deccryption
                new EventHandler<ActionEvent>() {
                    @Override
                    public void handle(final ActionEvent e) {
                            try {
                                FileEncrypterDecrypter fileEncrypterDecrypter
                                        = null;
                                try {
                                    fileEncrypterDecrypter = new FileEncrypterDecrypter(mode);
                                } catch (NoSuchPaddingException e1) {
                                    e1.printStackTrace();
                                } catch (NoSuchAlgorithmException e1) {
                                    e1.printStackTrace();
                                }

                                InputStream input = socket.getInputStream();
                                byte[] buffer = new byte[input.available()];
                                input.read(buffer);

                                File targetFile = new File("C:\\Users\\Win10\\Desktop\\IT\\newFile");
                                OutputStream outStream = new FileOutputStream(targetFile);
                                outStream.write(buffer);
                                outStream.flush();
                                outStream.close();

                                if (targetFile != null) {
                                    try {
                                        fileEncrypterDecrypter.decryptSessionKey(keyPair.getPrivate(), RSAEncrypter);
                                        fileEncrypterDecrypter.decryptFile(targetFile, finalModeHash);

                                    } catch (Exception e1) {
                                        e1.printStackTrace();
                                    }
                                }
                            } catch (IOException e2) {
                                e2.printStackTrace();
                            }
                            }
                });

        final GridPane inputGridPane = new GridPane();
        GridPane.setConstraints(openButton, 0, 0);
        GridPane.setConstraints(openButton2, 0, 20);
        inputGridPane.add(textField,1,1,1,1);
        inputGridPane.setHgap(6);
        inputGridPane.setVgap(6);
        inputGridPane.getChildren().addAll(openButton,openButton2);

        final Pane rootGroup = new VBox(12);
        rootGroup.getChildren().addAll(inputGridPane);
        rootGroup.setPadding(new Insets(12, 12, 12, 12));

        primaryStage.setScene(new Scene(rootGroup,300,275));

        primaryStage.show();
    }

    public void encryptPrivateKey(PrivateKey privateKey, String password) throws Exception {
        String keyString = getHashSHA_256(password); //password of user

        byte[] keyBytes = new byte[16];
        try {
            byte[] key = keyString.getBytes();
            int len = key.length;

            if (len > keyBytes.length) {
                len = keyBytes.length;
            }

            System.arraycopy(key, 0, keyBytes, 0, len);
        }catch (Exception ext){
            System.out.println(ext.getMessage());
        }

        SecretKeySpec key = new SecretKeySpec(keyBytes,"AES");
        FileEncrypterDecrypter edCBC = new FileEncrypterDecrypter(key,"AES/CBC/NoPadding");
        edCBC.encryptPrivateKeyCBC(privateKey,key,"new vector".getBytes());
    }

    public void decryptPrivateKey(String password) throws Exception {
        String keyString = getHashSHA_256(password); //password of user

        byte[] keyBytes = new byte[16];
        try {
            byte[] key = keyString.getBytes();
            int len = key.length;

            if (len > keyBytes.length) {
                len = keyBytes.length;
            }

            System.arraycopy(key, 0, keyBytes, 0, len);
        }catch (Exception ext){
            System.out.println(ext.getMessage());
        }

        SecretKeySpec key = new SecretKeySpec(keyBytes,"AES");
        FileEncrypterDecrypter edCBC = new FileEncrypterDecrypter(key,"AES/CBC/NoPadding");
        edCBC.decryptPrivateKeyCBC("new vector".getBytes());
    }

    public String getHashSHA_256(String password) throws Exception{
        String hash = null;
        byte[] passwordBytes = password.getBytes();

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte sha256[] = md.digest(passwordBytes);
        sha256 = Arrays.copyOf(sha256, 16);
        String hashString = bytesToHex(sha256);
        return  hashString;
    }

    private static String bytesToHex(byte[] hash) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }
}
