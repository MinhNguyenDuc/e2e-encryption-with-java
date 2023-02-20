import java.security.Key;
import java.util.Arrays;

// AESIngredient class, which is used to store AES key and IV parameter for AES encryption
public class AESIngredient {
    private byte[] ivParameterBytes;

    public byte[] getIvParameterBytes() {
        return ivParameterBytes;
    }

    public void setIvParameterBytes(byte[] ivParameterBytes) {
        this.ivParameterBytes = ivParameterBytes;
    }

    private Key aesKey;

    public Key getAesKey() {
        return aesKey;
    }

    public void setAesKey(Key aesKey) {
        this.aesKey = aesKey;
    }

    public AESIngredient(byte[] ivParameterBytes, Key aesKey) {
        this.ivParameterBytes = ivParameterBytes;
        this.aesKey = aesKey;
    }

    @Override
    public String toString() {
        return "AESIngredient [ivParameterBytes=" + Arrays.toString(ivParameterBytes) + ", aesKey=" + aesKey + "]";
    }
    
}
