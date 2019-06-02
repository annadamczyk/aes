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
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Server extends Application{
    private static ServerSocket serverSocket;
    private static Socket socket;
    public static void main(String[] args) throws InterruptedException {

        try {
            serverSocket = new ServerSocket(4999);
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            //while (true) {
                socket = serverSocket.accept();
                //OutputStream ou = socket.getOutputStream();
                //ou.write("Server says hello!".getBytes());
                //Thread.sleep(1000);
                //socket.close();
            //}
        } catch (IOException e) {
            e.printStackTrace();
        }
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        primaryStage.setTitle("Server");
        final FileChooser fileChooser = new FileChooser();
        final Button openButton = new Button("Choose a file to encoding...");

        SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
        RSA RSAEncrypter = new RSA();

        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        //String contents = new String(Files.readAllBytes(Paths.get("C:\\Users\\Win10\\IdeaProjects\\AES\\publicKeys.txt")));
        //System.out.println("publicKey SERVER: "+ contents);
        InputStream is2 = new FileInputStream("C:\\Users\\Win10\\IdeaProjects\\AES\\publicKeys.txt");
        BufferedReader buf2 = new BufferedReader(new InputStreamReader(is2));
        String line2 = buf2.readLine();
        StringBuilder sb2 = new StringBuilder();
        while(line2 != null){
            sb2.append(line2.trim());
            line2 = buf2.readLine();
        }
        System.out.println("Public key: "+sb2.toString());

        byte[] byteKey = Base64.getDecoder().decode(sb2.toString().trim());
        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");



        PublicKey publicKey = kf.generatePublic(X509publicKey); //TO DO:from client
        String test =RSAEncrypter.encrypt("Ania",publicKey);
        String encryptedSessionKey = RSAEncrypter.encrypt(Base64.getEncoder().encodeToString(secretKey.getEncoded()),publicKey);
        System.out.println("sessionKey SERVER: "+Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        System.out.println("encryptedSessionKey SERVER: "+encryptedSessionKey);

        //sending encrypted session key to client
        OutputStream outputStream = socket.getOutputStream();
        PrintWriter writer = new PrintWriter(outputStream, true);
        writer.println(test);
        //writer.println(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        outputStream.flush();

        String mode = null;
        String modeHash = null;

        //CBC
        modeHash = "ECB";
        mode = "AES/ECB/PKCS5Padding";

        //ECB
        //modeHash = "ECB";
        //mode = "AES/ECB/NoPadding";

        //CFB


        //OFB

        FileEncrypterDecrypter fileEncrypterDecrypter
                = new FileEncrypterDecrypter(secretKey, mode);


        String finalModeHash = modeHash;
        /*openButton2.setOnAction( //decryption
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
                });*/

        openButton.setOnAction( //encryption
                new EventHandler<ActionEvent>() {
                    @Override
                    public void handle(final ActionEvent e) {
                        File file = fileChooser.showOpenDialog(primaryStage);
                        if (file != null) {
                            try {
                                fileEncrypterDecrypter.encryptFile(file, finalModeHash,socket);

                            } catch (Exception e1) {
                                e1.printStackTrace();
                            }
                        }}
                });

        final GridPane inputGridPane = new GridPane();
        GridPane.setConstraints(openButton, 0, 0);
        //GridPane.setConstraints(openButton2, 0, 20);
        inputGridPane.setHgap(6);
        inputGridPane.setVgap(6);
        inputGridPane.getChildren().addAll(openButton);//,openButton2);

        final Pane rootGroup = new VBox(12);
        rootGroup.getChildren().addAll(inputGridPane);
        rootGroup.setPadding(new Insets(12, 12, 12, 12));

        primaryStage.setScene(new Scene(rootGroup,300,275));

        primaryStage.show();
    }
}
