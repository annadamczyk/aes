package sample;

import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Pane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.KeyPair;

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

        SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
        RSA RSAEncrypter = new RSA();
        KeyPair keyPair = RSAEncrypter.generateKeyPair(2048);
        String encryptedSessionKey = RSAEncrypter.encrypt(secretKey.toString(),keyPair.getPublic());



        String mode = null;
        String modeHash = null;

        //CBC
        modeHash = "CBC";
        mode = "AES/CBC/PKCS5Padding";

        //ECB
        //modeHash = "ECB";
        //mode = "AES/ECB/NoPadding";

        //CFB


        //OFB

        FileEncrypterDecrypter fileEncrypterDecrypter
                = new FileEncrypterDecrypter(secretKey, mode);


        String finalModeHash = modeHash;
        openButton2.setOnAction( //decryption
                new EventHandler<ActionEvent>() {
                    @Override
                    public void handle(ActionEvent event) {
                        //File file = fileChooser.showOpenDialog(primaryStage);
                       // if (file != null) {

                            try {
                                //InputStream input = socket.getInputStream();
                                //FileOutputStream fileOutputStream = new FileOutputStream(f);
                                //byte[] bytes = new byte[(int)f.length()];
                                //input.read(bytes,0, bytes.length);
                                //fileOutputStream.write(bytes,0,bytes.length);
                                //fileEncrypterDecrypter.decryptFile(file, finalModeHash);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }

                        //}
                    }
                });

        openButton.setOnAction( //encryption
                new EventHandler<ActionEvent>() {
                    @Override
                    public void handle(final ActionEvent e) {


                        //File file = fileChooser.showOpenDialog(primaryStage);


                        //if (file != null) {
                            try {

                                InputStream input = socket.getInputStream();
                                byte[] buffer = new byte[input.available()];
                                input.read(buffer);

                                File targetFile = new File("C:\\Users\\Win10\\Desktop\\IT\\newFile");
                                OutputStream outStream = new FileOutputStream(targetFile);
                                outStream.write(buffer);
                            } catch (IOException e2) {
                                e2.printStackTrace();
                            }

                            }

                        //}}
                });

        final GridPane inputGridPane = new GridPane();
        GridPane.setConstraints(openButton, 0, 0);
        GridPane.setConstraints(openButton2, 0, 20);
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
