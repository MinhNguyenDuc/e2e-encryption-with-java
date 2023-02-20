import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// Helper class, where all cryptographic and file functions are implemented
public class Helper {

    // Generates 16 random bytes
    public static byte[] generate16RandomBytes() throws NoSuchAlgorithmException {
        byte[] arr = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(arr);
        return arr;
    }

    public static byte[] encryptBytes(byte[] input, Key key) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedMessageBytes = c.doFinal(input);
        return encryptedMessageBytes;
    }

    public static byte[] creatSignatureWithSHA1withRSA(byte[] input, PrivateKey key)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(key);
        signature.update(input);
        return signature.sign();
    }

    // Read RSA key from key file
    public static Key readRSAKey(String keyPath) throws IOException, NullPointerException,
            NoSuchAlgorithmException, InvalidKeySpecException, ClassNotFoundException {
        ObjectInputStream in = new ObjectInputStream(new FileInputStream(keyPath));
        Key key = (Key) in.readObject();
        in.close();
        return key;
    }

    // Verify if the signature is valid
    public static boolean verifySignature(byte[] input, byte[] signature, PublicKey key)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance("SHA1withRSA");
        sign.initVerify(key);
        sign.update(input);
        return sign.verify(signature);
    }

    // Decrypt input bytes with RSA
    public static byte[] decryptWithRSA(byte[] encryptedBytes, PrivateKey key) throws InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedBytes);
    }

    // Merge 2 bytes arrays into 1
    public static byte[] merge2BytesArray(byte[] a1, byte[] a2) {

        byte[] combined = new byte[a1.length + a1.length];

        System.arraycopy(a1, 0, combined, 0, a1.length);
        System.arraycopy(a2, 0, combined, a1.length, a2.length);
        return combined;
    }

    // Convert bytes to Base64 String, for output printing purpose
    public static String convertBytesToBase64String(byte[] input) {
        return Base64.getEncoder().encodeToString(input);
    }

    // Prepare transferable message for Key Exchange phase
    public static KeyExcMessage prepareMessage(byte[] randomBytes, String userId, String receiverPublicKeyPath,
            String senderPrivateKeyPath) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NullPointerException,
            InvalidKeySpecException, ClassNotFoundException, IOException {

        PublicKey receiverPublicKey = (PublicKey) readRSAKey(receiverPublicKeyPath);
        PrivateKey senderPrivateKey = (PrivateKey) readRSAKey(senderPrivateKeyPath);

        byte[] encryptBytes = encryptBytes(randomBytes, receiverPublicKey);

        byte[] signature = creatSignatureWithSHA1withRSA(encryptBytes, senderPrivateKey);

        KeyExcMessage message = new KeyExcMessage(userId, encryptBytes, signature);
        return message;
    }

    // Generates AES-256 key
    public static Key generateAESKey(byte[] inputBytes) throws NoSuchAlgorithmException, IOException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        Key key = new SecretKeySpec(inputBytes, "AES");
        return key;
    }

    // Read content from file
    public static File readFromFile(String filePath) {
        return new File(filePath);
    }

    // Write bytes to file (any bytes)
    public static void writeBytesToFile(byte[] input, String filePath) throws IOException {
        File file = new File(filePath);
        FileOutputStream outputStream = new FileOutputStream(file);
        outputStream.write(input);
        outputStream.close();
    }

    // Read bytes from file
    public static byte[] readBytesFromFile(String filePath) throws IOException {
        return Files.readAllBytes(Paths.get(filePath));
    }

    // Encrypt file with AES-256 with input iv parameter and return encrypted bytes
    public static byte[] encryptFileWithAES256(Key key, File file, byte[] ivParameterBytes)
            throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivParameterBytes));

        FileInputStream inputStream = new FileInputStream(file);
        byte[] inputBytes = new byte[(int) file.length()];
        inputStream.read(inputBytes);

        inputStream.close();

        byte[] outputBytes = cipher.doFinal(inputBytes);
        return outputBytes;
    }

    // Decrypt bytes using AES 256 with input iv parameter
    public static byte[] decryptFileWithAES256(Key key, byte[] inputBytes, byte[] ivParameterBytes)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivParameterBytes);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        return cipher.doFinal(inputBytes);
    }

    // create hash of a file with MD5
    public static String hashFileName(String fileName, String userId) throws NoSuchAlgorithmException {
        String salt = "gfhk7346";
        String preHashString = userId + ":" + salt + ":" + fileName;

        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        byte[] inputBytes = preHashString.getBytes();
        byte[] hashBytes = messageDigest.digest(inputBytes);

        return convertBytesToHexadecimal(hashBytes);
    }

    // Convert bytes to Hexadecimal (for output printing)
    public static String convertBytesToHexadecimal(byte[] input) {
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : input) {
            stringBuilder.append(String.format("%02x", b & 0xff));
        }
        return stringBuilder.toString();
    }
}
