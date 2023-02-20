import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
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

public class Client {

    // This variable is used to store the path to the server's private key
    private static final String SERVER_PUBLIC_KEY_PATH = "./server.pub";

    // This variable is used to store the path to the private key of the client (incase it is in a folder)
    // By default, the key will be stored in the current working directory
    private static final String CLIENT_PRIVATE_KEY_PATH = "./";

    public static void main(String[] args) throws Exception {

        System.out.println("Starting client...");

        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userId = args[2];
        String fileName = args[3];

        if (host == null || port == 0 || userId == null || fileName == null) {
            System.out.println("Please enter the correct arguments");
            System.exit(0);
        }

        Socket client = new Socket(host, port);
        ObjectOutputStream oos = new ObjectOutputStream(client.getOutputStream());
        ObjectInputStream ois = new ObjectInputStream(client.getInputStream());

        // Key Exchange Stage
        System.out.println("Starting key exchange stage...");

        AESIngredient ingredient = keyExchangeStage(oos, ois, userId, host, port, SERVER_PUBLIC_KEY_PATH,
                CLIENT_PRIVATE_KEY_PATH, fileName);

        // File Exchange Stage
        System.out.println("Starting file exchange stage...");
        fileExchangeStage(oos, userId, host, port, ingredient, fileName);

        client.close();
    }

    // Key exchange Stage
    private static AESIngredient keyExchangeStage(ObjectOutputStream oos, ObjectInputStream ois, String userId,
            String host, int port, String serverPublicKeyPath, String clientPrivateKeyPath, String fileName)
            throws UnknownHostException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NullPointerException,
            InvalidKeySpecException, ClassNotFoundException, InvalidAlgorithmParameterException {

        byte[] clientBytes = Helper.generate16RandomBytes();
        KeyExcMessage message = Helper.prepareMessage(clientBytes, userId, serverPublicKeyPath,
                clientPrivateKeyPath + userId + ".prv");
        oos.writeObject(message);

        KeyExcMessage receivedMsg = (KeyExcMessage) ois.readObject();

        PrivateKey clientPrivateKey = (PrivateKey) Helper.readRSAKey(clientPrivateKeyPath + userId + ".prv");
        PublicKey serverPublicKey = (PublicKey) Helper.readRSAKey(serverPublicKeyPath);

        // Use client private key to decrypt the message and get the server bytes
        byte[] serverBytes = Helper.decryptWithRSA(receivedMsg.getEncryptedBytes(), clientPrivateKey);

        byte[] finalKeyBytes = Helper.merge2BytesArray(clientBytes, serverBytes);

        boolean isVerified = Helper.verifySignature(receivedMsg.getEncryptedBytes(), receivedMsg.getSignature(),
                serverPublicKey);
        if (isVerified == false) {
            System.out.println("Verify signature failed");
            return null;
        }
        System.out.println("Verify signature success");
        Key eAES256KeY = Helper.generateAESKey(finalKeyBytes);

        System.out.println("\n AES Key in Base64: " + Helper.convertBytesToBase64String(eAES256KeY.getEncoded()));

        return new AESIngredient(clientBytes, eAES256KeY);
    }

    // File exchange stage
    private static void fileExchangeStage(ObjectOutputStream oos, String userId, String host, int port,
            AESIngredient ingredient, String fileName) throws UnknownHostException, IOException, InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, NullPointerException, InvalidKeySpecException, ClassNotFoundException {

        byte[] encryptedFile = Helper.encryptFileWithAES256(ingredient.getAesKey(), Helper.readFromFile(fileName),
                ingredient.getIvParameterBytes());

        FileMessage fileMsg = new FileMessage(userId, Helper.hashFileName(fileName, userId), encryptedFile);

        oos.writeObject(fileMsg);

        System.out.println("File is sent to server");

    }
}