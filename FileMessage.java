import java.io.Serializable;

// FileMessage class, which is used to send files (as DTO)
public class FileMessage implements Serializable {

    private String userId;

    public FileMessage(String userId, String fileName, byte[] encryptedContent) {
        this.userId = userId;
        this.fileName = fileName;
        this.encryptedContent = encryptedContent;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    private String fileName;

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    private byte[] encryptedContent;

    public byte[] getEncryptedContent() {
        return encryptedContent;
    }

    public void setEncryptedContent(byte[] encryptedContent) {
        this.encryptedContent = encryptedContent;
    }

    @Override
    public String toString() {
        return "FileMessage [userId=" + userId + ", fileName=" + fileName + ", encryptedContent="
                + Helper.convertBytesToBase64String(encryptedContent) + "]";
    }

}
