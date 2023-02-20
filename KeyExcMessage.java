import java.io.Serializable;
import java.util.Base64;

// Key Exchange Message class, which is used to send key exchange message (as DTO)
public class KeyExcMessage implements Serializable{

    private String userID;
    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    private byte[] encryptedBytes;
    public byte[] getEncryptedBytes() {
        return encryptedBytes;
    }

    public void setEncryptedBytes(byte[] encryptedBytes) {
        this.encryptedBytes = encryptedBytes;
    }

    private byte[] signature;
    
    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public KeyExcMessage(String userID, byte[] encryptedBytes, byte[] signature) {
        this.userID = userID;
        this.encryptedBytes = encryptedBytes;
        this.signature = signature;
    }

    @Override
    public String toString() {
        return "Message [userID=" + userID + ", encryptedBytes=" + Base64.getEncoder().encodeToString(encryptedBytes) + ", signature="
                + Base64.getEncoder().encodeToString(signature) + "]";
    }
}
