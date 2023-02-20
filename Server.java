import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;

public class Server {

    private static ServerSocket server;

    // This variable is used to store the path to the server's private key
    private static String serverPrivateKeyPath = "./server.prv";
    
    // This variable is used to store the path to the public key of the client (incase it is in a folder)
    // By default, the key will be stored in the current working directory
    private static String clientPublicKeyPath = "./";

    // This variable is used to store the path to file (incase it is in a folder)
    // By default, the file will be stored in the current working directory
    private static String fileStoragePath = "./";

    public static void main(String[] args) throws IOException, ClassNotFoundException {

        if (args[0] == null) {
            System.out.println("Please enter the correct arguments");
            System.exit(0);
        }

        int port = Integer.parseInt(args[0]);

        System.out.println("Starting server on port " + port);

        server = new ServerSocket(port);

        while (true) {
            Socket s = server.accept();
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

            AESIngredient ingredient = null;

            try {
                Object keyExObj = ois.readObject();
                if (keyExObj instanceof KeyExcMessage) {
                    ingredient = keyExchangeStage(keyExObj, serverPrivateKeyPath, clientPublicKeyPath, oos);
                }

                Object fileObj = ois.readObject();
                fileExchangeStage(fileObj, ingredient);
                ingredient = null;
            } catch (Exception e) {
                e.printStackTrace();
                System.err.println("Error in server");
            }
        }
    }

    private static AESIngredient keyExchangeStage(Object receivedObj, String serverPrivateKeyPath,
            String clientPublicKeyPath, ObjectOutputStream oos) throws NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NullPointerException,
            InvalidKeySpecException, ClassNotFoundException, IOException, SignatureException {
        System.out.println("===================KEY EXCHANGE STAGE===================");
        KeyExcMessage receivedMsg = (KeyExcMessage) receivedObj;

        String userId = receivedMsg.getUserID();
        System.out.println("User ID: " + userId);

        PrivateKey serverPrivateKey = (PrivateKey) Helper.readRSAKey(serverPrivateKeyPath);
        PublicKey clientPublicKey = (PublicKey) Helper.readRSAKey(clientPublicKeyPath + userId + ".pub");
        byte[] clientBytes = Helper.decryptWithRSA(receivedMsg.getEncryptedBytes(), serverPrivateKey);

        System.out.println("Client bytes in Base64: " + Helper.convertBytesToBase64String(clientBytes));

        byte[] serverBytes = Helper.generate16RandomBytes();

        System.out.println("Server bytes in Base64: " + Helper.convertBytesToBase64String(serverBytes));

        byte[] finalKeyBytes = Helper.merge2BytesArray(clientBytes, serverBytes);

        boolean isVerified = Helper.verifySignature(receivedMsg.getEncryptedBytes(),
                receivedMsg.getSignature(), clientPublicKey);

        if (isVerified == false) {
            System.out.println("Verify signature failed");
            return null;
        }
        System.out.println("Verify signature success");
        KeyExcMessage responseMsg = Helper.prepareMessage(serverBytes, "server", clientPublicKeyPath + userId + ".pub",
                serverPrivateKeyPath);
        oos.writeObject(responseMsg);

        Key eAES256KeY = Helper.generateAESKey(finalKeyBytes);

        System.out.println("===================END KEY EXCHANGE STAGE===================");
        return new AESIngredient(clientBytes, eAES256KeY);
    }

    private static void fileExchangeStage(Object receivedObj, AESIngredient ingredient)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, NullPointerException, InvalidKeySpecException, ClassNotFoundException, IOException,
            InvalidAlgorithmParameterException {
        System.out.println("===================FILE EXCHANGE STAGE===================");
        FileMessage fileMsg = (FileMessage) receivedObj;

        System.out.println("File name: " + fileMsg.getFileName());

        byte[] contentBytes = Helper.decryptFileWithAES256(ingredient.getAesKey(), fileMsg.getEncryptedContent(),
                ingredient.getIvParameterBytes());

        Helper.writeBytesToFile(contentBytes, fileStoragePath + fileMsg.getFileName());
        String contentData = new String(contentBytes, StandardCharsets.UTF_8);
        System.out.println("File content: " + contentData);
    }
}