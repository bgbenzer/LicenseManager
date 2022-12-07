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

    public byte[] server(byte[] encryptedMessageBytes) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

//        ServerSocket serverSocket = new ServerSocket(5000);
//        Socket socket = serverSocket.accept();

        System.out.println("Server -- Server is being requested...");

        //Get encrypted message from client
//        DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
//        int length = dataInputStream.readInt();
//        byte[] encryptedMessageBytes = new byte[length];
//        dataInputStream.readFully(encryptedMessageBytes,0, encryptedMessageBytes.length);

        String stringEncryptedMessageBytes = new String(encryptedMessageBytes);
        System.out.println("Server -- Incoming Encrypted Text: " + stringEncryptedMessageBytes);

        //Decrypt client encrypted message
        String finALE = this.decrypt(encryptedMessageBytes);
        System.out.println("Server -- Decrypted Text: " + finALE);

        //Hash decrypted message for send client
        String hash = this.md5Hash(finALE);
        System.out.println("Server -- MD5 Plain License Text: " + hash);

        //Sign hashed message
        byte[] signedMessageBytes = this.sign(hash);
        String stringSignedMessageBytes = new String(signedMessageBytes);
        System.out.println("Server -- Digital Signature: " + stringSignedMessageBytes);

        //Send signed message to client
//        DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
//        dataOutputStream.writeInt(signedMessageBytes.length);
//        dataOutputStream.write(signedMessageBytes);

        return signedMessageBytes;
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
