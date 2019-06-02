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
import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class Client extends Application {
    private static Socket socket;
    public static void main(String[] args) throws IOException {
        //launch(args);
        socket = new Socket("localhost",4999);


        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        primaryStage.setTitle("Client");
        final FileChooser fileChooser = new FileChooser();
        final Button openButton = new Button("decoding...");
        final Button openButton2 = new Button("potwierdź");
        TextField textField = new TextField();

        //generate public and private keys for client
        RSA RSAEncrypter = new RSA();
        KeyPair keyPair = RSAEncrypter.generateKeyPair(2048);

//testy RSA
//        String test = RSAEncrypter.encrypt("ANia",keyPair.getPublic());
//        System.out.println(test);
//        System.out.println(RSAEncrypter.decrypt(test, keyPair.getPrivate()));


        //add public key to file
        OutputStream outputStream = new FileOutputStream("C:\\Users\\Win10\\IdeaProjects\\AES\\publicKeys.txt", false);
        PublicKey publicKey = keyPair.getPublic();
        byte[] encodedPublicKey = publicKey.getEncoded();
        String b64PublicKey = Base64.getEncoder().encodeToString(encodedPublicKey);
        System.out.println("Public key CLIENT: "+ b64PublicKey.trim());
        //byte[] strToBytes = keyPair.getPublic().toString().getBytes();
        outputStream.write(b64PublicKey.trim().getBytes());
        outputStream.flush();
        outputStream.close();

        OutputStream outToServer = socket.getOutputStream();
        outputStream.write(b64PublicKey.getBytes());
        DataOutputStream out = new DataOutputStream(outToServer);
        //add private key to file
        //TO DO: CBC private key
        PrivateKey privateKey = keyPair.getPrivate();
        byte[] encodedPrivateKey = privateKey.getEncoded();
        String b64PrivateKey = Base64.getEncoder().encodeToString(encodedPrivateKey);
        outputStream = new FileOutputStream("C:\\Users\\Win10\\IdeaProjects\\AES\\privateKeys.txt", false);

        outputStream.write(b64PrivateKey.getBytes());
        outputStream.close();

        //modeHash and mode from SERVER
        final String modeHash = "ECB";
        final String mode = "AES/ECB/PKCS5Padding";

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
}
