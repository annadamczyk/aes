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
import java.io.File;
import java.security.KeyPair;

public class Main extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception{
        final FileChooser fileChooser = new FileChooser();
        final Button openButton = new Button("Choose a file to encoding...");
        final Button openButton2 = new Button("Choose a file to decoding...");

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
                        File file = fileChooser.showOpenDialog(primaryStage);
                        if (file != null) {

                                try {
                                    fileEncrypterDecrypter.decryptFile(file, finalModeHash);
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }

                        }
                    }
                });

        openButton.setOnAction( //encryption
                new EventHandler<ActionEvent>() {
                    @Override
                    public void handle(final ActionEvent e) {


                        File file = fileChooser.showOpenDialog(primaryStage);


                        if (file != null) {
                                    try {
                                        //fileEncrypterDecrypter.encryptFile(file, finalModeHash);
                                    } catch (Exception e1) {
                                        e1.printStackTrace();
                                    }

                        }}
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

    public static void main(String[] args) {
        launch(args);
    }
}
