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

import javax.crypto.spec.SecretKeySpec;
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
    private static String message = null;
    public static void main(String[] args) throws InterruptedException, ClassNotFoundException {

        try {
            serverSocket = new ServerSocket(4999);
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            socket = serverSocket.accept();
            if(message == null) {

                ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                String messageClient = (String) ois.readObject();
                System.out.println(messageClient);
                message = messageClient;
            }
            launch(args);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    //generowanie klucza z początkową wartościa - czas systemowy
    static byte[] generateKey(int lenght) throws UnsupportedEncodingException {
        byte[] keyBytes = new byte[lenght];
        try {
            long time = System.currentTimeMillis();
            //final ByteBuffer bb = ByteBuffer.allocate(Integer.SIZE / Byte.SIZE);
            //bb.order(ByteOrder.LITTLE_ENDIAN);
            //bb.putInt(Math.toIntExact(time));
            String timeString = String.valueOf(time);
            byte[] key = timeString.getBytes();


            int len = key.length;

            if (len > keyBytes.length) {
                len = keyBytes.length;
            }

            System.arraycopy(key, 0, keyBytes, 0, len);
        }catch (Exception ext){
            System.out.println(ext.getMessage());
        }
        return keyBytes;
    }

    @Override
    public void start(Stage primaryStage) throws Exception {

        primaryStage.setTitle("Server");
        final FileChooser fileChooser = new FileChooser();
        final Button openButton = new Button("Choose a file to encoding...");

        //SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
        SecretKeySpec secretKey = new SecretKeySpec(generateKey(16), "AES");
        RSA RSAEncrypter = new RSA();

        InputStream is2 = new FileInputStream("C:\\Users\\Win10\\IdeaProjects\\AES\\publicKeys.txt");
        BufferedReader buf2 = new BufferedReader(new InputStreamReader(is2));
        String line2 = buf2.readLine();
        System.out.println(line2);
        StringBuilder sb2 = new StringBuilder();
        StringBuilder sb3 = new StringBuilder();
        while(line2 != null){
            sb2.append(line2.trim());
            sb3.append(line2);
            line2 = buf2.readLine();
        }

        byte[] byteKey = Base64.getDecoder().decode(sb2.toString());
        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        PublicKey publicKey = kf.generatePublic(X509publicKey);

        System.out.println("Session key :"+secretKey.getEncoded().toString());
        String encryptedSessionKey = RSAEncrypter.encrypt(Base64.getEncoder().encodeToString(secretKey.getEncoded()),publicKey);
        System.out.println("sessionKey SERVER: "+Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        System.out.println("encryptedSessionKey SERVER: "+encryptedSessionKey);

        OutputStream outputStream = socket.getOutputStream();
        PrintWriter writer = new PrintWriter(outputStream, true);
        writer.println(encryptedSessionKey);
        outputStream.flush();

        String mode = null;
        String modeHash = null;

        //ECB
        //modeHash = "ECB";
        //mode = "AES/ECB/NoPadding";

        //CBC
        //modeHash = "CBC";
        //mode = "AES/CBC/NoPadding";

        //CFB
        modeHash = "CFB";
        mode = "AES/CFB/PKCS5PADDING";

        //OFB
        //modeHash = "OFB";
        //mode = "AES/OFB/NoPadding";

        FileEncrypterDecrypter fileEncrypterDecrypter = new FileEncrypterDecrypter(secretKey, mode);
        String finalModeHash = modeHash;
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
