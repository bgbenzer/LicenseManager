import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Client {

    private String userName;
    private String serialNumber;
    private String MACAddress;
    private String diskSerialNumber;
    private String motherboardSerialNumber;
    private byte[] publicKey;

    public Client(String MACAddress, String diskSerialNumber, String motherboardSerialNumber) throws IOException {
        this.userName = "MURAD";
        this.serialNumber= "1234-4321-1234";
        this.MACAddress = MACAddress;
        this.diskSerialNumber = diskSerialNumber;
        this.motherboardSerialNumber = motherboardSerialNumber;
        this.publicKey = readAsByte("public.key");
    }
    public Client() throws IOException {
        this.userName = "MURAD";
        this.serialNumber= "1234-4321-1234";
        this.publicKey = readAsByte("public.key");
    }

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Client client = new Client();

        String[] fileContent = readFile("license.txt");
        if(fileContent != null){

        }else{
            System.out.println("===========================================");
//            System.out.println("USTAM O DOSYA HAKKIN RAHMETİNE KAVUŞMUŞ");
            client.setMACAddress(client.getMacAddress()); // MAC ADDRESS
//            System.out.println("My Mac Address: "+ client.getMACAddress());
            client.setDiskSerialNumber(client.getDiskSerialNumber());
//            System.out.println("My Disk Serial Number: "+ client.getDiskSN());
            client.setMotherboardSerialNumber(client.getMotherboardSerialNumber());
//            System.out.println("My Motherboard Serial Number: "+ client.getMotherboardSN());
            String concatVersion = client.getUserName()+"$"+client.getSerialNumber()+"$"+client.getMACAddress()+"$"+client.getDiskSN()+"$"+client.getMotherboardSN();

            File publicKeyFile = new File("public.key");
            byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, keyFactory.generatePublic(publicKeySpec));

            byte[] secretMessageBytes = concatVersion.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);


            Socket socket = new Socket("localhost", 5000);
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
            dataOutputStream.writeInt(encryptedMessageBytes.length);
            dataOutputStream.write(encryptedMessageBytes);

//            ServerSocket serverSocket = new ServerSocket(5000);
//            Socket socket2 = serverSocket.accept();

            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
            int length = dataInputStream.readInt();
            byte[] signedMessageBytes = new byte[length];
            dataInputStream.readFully(signedMessageBytes,0, encryptedMessageBytes.length);

//            String hash = new String(signedMessageBytes);
//            System.out.println(hash);

            KeyFactory keyFactory2 = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec2 = new X509EncodedKeySpec(publicKeyBytes);

            Cipher encryptCipher2 = Cipher.getInstance("RSA");
            encryptCipher2.init(Cipher.DECRYPT_MODE, keyFactory2.generatePublic(publicKeySpec2));
            byte[] decryptedMessageBytes = encryptCipher2.doFinal(signedMessageBytes);
            String stringHash = new String(decryptedMessageBytes);
            System.out.println(stringHash);


        }






        //1)license.txt var mı bak
        //2)varsa public key ile very et
        //3)licensemanager hem public hem private key tutuyor, client sadece public tutuyor
        //3) Lincese.txt yoksa şunları al:1. the username (string)
        // the serial number (string having format of ####-####-####)
        // MAC address of the Ethernet device of the host system (string)
        // Disk serial number (string)
        // Motherboard serial number (string)

        //bunları $ ile concat et
        //publickeyle encrypt et (RSA ile)

        //encryprt datayı licensemanager'a at
        //decrypte et
        //decrypted datanın hashini al (md5 ile)
        //hashi private key ile imzala
        //clienta at

        //clientta public key ile hardware datasının hashini alıpkontrol et
        //eğer licensemanager'dan geliyorsa license.txt'ye bas

    }

    public String getMotherboardSerialNumber() {
        String result = "";
        try {
            File file = File.createTempFile("realhowto",".vbs");
            file.deleteOnExit();
            FileWriter fw = new java.io.FileWriter(file);

            String vbs =
                    "Set objWMIService = GetObject(\"winmgmts:\\\\.\\root\\cimv2\")\n"
                            + "Set colItems = objWMIService.ExecQuery _ \n"
                            + "   (\"Select * from Win32_BaseBoard\") \n"
                            + "For Each objItem in colItems \n"
                            + "    Wscript.Echo objItem.SerialNumber \n"
                            + "    exit for  ' do the first cpu only! \n"
                            + "Next \n";

            fw.write(vbs);
            fw.close();
            Process p = Runtime.getRuntime().exec("cscript //NoLogo " + file.getPath());
            BufferedReader input =
                    new BufferedReader
                            (new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = input.readLine()) != null) {
                result += line;
            }
            input.close();
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return result;
    }

    public String getDiskSerialNumber() {
        String result = "";
        try {
            File file = File.createTempFile("realhowto",".vbs");
            file.deleteOnExit();
            FileWriter fw = new java.io.FileWriter(file);

            String vbs = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")\n"
                    +"Set colDrives = objFSO.Drives\n"
                    +"Set objDrive = colDrives.item(\"C\")\n"
                    +"Wscript.Echo objDrive.SerialNumber";  // see note
            fw.write(vbs);
            fw.close();
            Process p = Runtime.getRuntime().exec("cscript //NoLogo " + file.getPath());
            BufferedReader input =
                    new BufferedReader
                            (new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = input.readLine()) != null) {
                result += line;
            }
            input.close();
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return result;
    }

    public String getMacAddress() throws UnknownHostException, SocketException {
        InetAddress localHost = InetAddress.getLocalHost();
        NetworkInterface ni = NetworkInterface.getByInetAddress(localHost);
        byte[] mac = ni.getHardwareAddress();

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < mac.length; i++) {
            sb.append(String.format(
                    "%02X%s", mac[i],
                    (i < mac.length - 1) ? "-" : ""));
        }

        return sb.toString();
    }

    public static String[] readFile(String path) {

        try {
            int i = 0;
            int length = Files.readAllLines(Paths.get(path)).size();
            String[] results = new String[length];								//Reading files.
            for (String line : Files.readAllLines(Paths.get(path))) {
                results[i++] = line;
            }
            return results;
        }
        catch (IOException e) {
//            e.printStackTrace();
            return null;
        }

    }

    public static void writeToFile(String str1, String outputFile){

        File file = new File(outputFile);

        try{

            file.createNewFile();
            FileWriter writer = new FileWriter(outputFile,true);

            writer.write(str1);
            writer.write("\n");

            writer.close();
        }
        catch(IOException e){
            System.out.println("error");
        }

    }
    public static byte[] readAsByte(String fileName) throws IOException {
        byte[] bytes = Files.readAllBytes(Paths.get(fileName));
        return bytes;
    }


    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getMACAddress() {
        return MACAddress;
    }

    public void setMACAddress(String MACAddress) {
        this.MACAddress = MACAddress;
    }

    public String getDiskSN() {
        return diskSerialNumber;
    }

    public void setDiskSerialNumber(String diskSerialNumber) {
        this.diskSerialNumber = diskSerialNumber;
    }

    public String getMotherboardSN() {
        return motherboardSerialNumber;
    }

    public void setMotherboardSerialNumber(String motherboardSerialNumber) {
        this.motherboardSerialNumber = motherboardSerialNumber;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

}
