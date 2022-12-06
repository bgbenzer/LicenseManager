import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class LicenseManager {

    private byte[] privateKey;
    private byte[] publicKey;

    public LicenseManager(){

    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        LicenseManager licenseManager = new LicenseManager();

        ServerSocket serverSocket = new ServerSocket(5000);
        Socket socket = serverSocket.accept();

        System.out.println("Client is connecting");

        DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
        int length = dataInputStream.readInt();
        byte[] encryptedMessageBytes = new byte[length];
        dataInputStream.readFully(encryptedMessageBytes,0, encryptedMessageBytes.length);

        String finALE = licenseManager.decrypt(encryptedMessageBytes);

        String hash = licenseManager.md5Hash(finALE);

        System.out.println(hash);

        byte[] signedMessageBytes = licenseManager.sign(hash);

        DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
        dataOutputStream.writeInt(signedMessageBytes.length);
        dataOutputStream.write(signedMessageBytes);


//        String[] data = finALE.split("\\$");


    }


    public String decrypt(byte[]encryptedMessageBytes) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        File privateKeyFile = new File("private.key");
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
        this.privateKey = privateKeyBytes;

        KeyFactory keyFactory2 = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        Cipher encryptCipher2 = Cipher.getInstance("RSA");
        encryptCipher2.init(Cipher.DECRYPT_MODE, keyFactory2.generatePrivate(privateKeySpec));

        byte[] decryptedMessageBytes = encryptCipher2.doFinal(encryptedMessageBytes);

        String finALE = new String(decryptedMessageBytes);
        return finALE;
    }


    public byte[] sign(String hash) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec2 = new PKCS8EncodedKeySpec(privateKey);

        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyFactory.generatePrivate(privateKeySpec2));

        byte[] signedMessageBytes = encryptCipher.doFinal(hash.getBytes());
        return signedMessageBytes;
    }

    public String md5Hash(String finALE) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(finALE.getBytes());
        byte[] digest = md.digest();
        String hash = DatatypeConverter.printHexBinary(digest).toUpperCase();
        return hash;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }
}
