import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Client {

    private String userName;
    private String serialNumber;
    private String MACAddress;
    private String diskSerialNumber;
    private String motherboardSerialNumber;
    private byte[] publicKey;

    public Client() throws IOException {
        this.userName = "MURAD";
        this.serialNumber= "1234-4321-1234";
        this.publicKey = readAsByte("public.key");
    }

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Client client = new Client();
        System.out.println("Client started...");
        client.setMACAddress(client.getMacAddress()); // MAC ADDRESS
        System.out.println("My MAC: "+ client.getMACAddress());

        client.setDiskSerialNumber(client.getDiskSerialNumber());
        System.out.println("My Disk ID: "+ client.getDiskSN());

        client.setMotherboardSerialNumber(client.getMotherboardSerialNumber());
        System.out.println("My Motherboard ID: "+ client.getMotherboardSN());

        LicenseManager licenseManager = new LicenseManager();
        System.out.println("LicenseManager service started...");

        byte[] fileContent = readAsByte("license.txt");

        if(fileContent != null){
            //Take public key for decrypt license.txt
            File publicKeyFile = new File("public.key");
            byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

            Cipher encryptCipher2 = Cipher.getInstance("RSA");
            encryptCipher2.init(Cipher.DECRYPT_MODE, keyFactory.generatePublic(publicKeySpec));

            try{
                byte[] decryptedMessageBytes = encryptCipher2.doFinal(fileContent);
                String decryptedLicenseText = new String(decryptedMessageBytes);
                System.out.println("Client -- License file is found.");

                //Create rawLicenseText for comparing with license.txt
                String rawLicenseText = client.getUserName()+"$"+client.getSerialNumber()+"$"+client.getMACAddress()+"$"+client.getDiskSN()+"$"+client.getMotherboardSN();
                System.out.println("Client -- Raw License Text: " + rawLicenseText);

                //MD5 Hashing for raw license text
                String rawLicenseTextHash = licenseManager.md5Hash(rawLicenseText);
                System.out.println("Client -- MD5 License Text: " + rawLicenseTextHash);

                //Compare client hash data with server hash data
                if(rawLicenseTextHash.equals(decryptedLicenseText)) {
                    System.out.println("Client -- Succeed. The license is correct.");
                }
                else {
                    System.out.println("Client -- The license file has been broken!!");
                    createLicense(client,  licenseManager);
                }
            }catch(Exception e){
                System.out.println("Client -- The license file has been broken!!");
                createLicense(client,  licenseManager);
            }



        }else{
            System.out.println("Client -- License file is not found.");

            createLicense(client, licenseManager);

        }
    }


    public static void createLicense(Client client, LicenseManager licenseManager) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        //Create rawLicenseText
        String rawLicenseText = client.getUserName()+"$"+client.getSerialNumber()+"$"+client.getMACAddress()+"$"+client.getDiskSN()+"$"+client.getMotherboardSN();
        System.out.println("Client -- Raw License Text: " + rawLicenseText);

        //Take public key at public.key
        File publicKeyFile = new File("public.key");
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyFactory.generatePublic(publicKeySpec));

        //Encrypt raw license text for send server
        byte[] secretMessageBytes = rawLicenseText.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);
        String encryptedLicenseText = new String(encryptedMessageBytes);
        System.out.println("Client -- Encrypted License Text: " + encryptedLicenseText);

        //Create raw license text hash for compare server response
        String rawLicenseTextHash = licenseManager.md5Hash(rawLicenseText);
        System.out.println("Client -- MD5 License Text: " + rawLicenseTextHash);

        //Send encrypted data to server with socket
//            Socket socket = new Socket("localhost", 5000);
//            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
//            dataOutputStream.writeInt(encryptedMessageBytes.length);
//            dataOutputStream.write(encryptedMessageBytes);

        byte[] signedMessageBytes = licenseManager.server(encryptedMessageBytes);

        //Get signed message which server response
//            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
//            int length = dataInputStream.readInt();
//            byte[] signedMessageBytes = new byte[length];
//            dataInputStream.readFully(signedMessageBytes,0, encryptedMessageBytes.length);

//            System.out.println("Client -- License is not found.");

        KeyFactory keyFactory2 = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec2 = new X509EncodedKeySpec(publicKeyBytes);

        //Decrypt signed message for compare two hash datas
        Cipher encryptCipher2 = Cipher.getInstance("RSA");
        encryptCipher2.init(Cipher.DECRYPT_MODE, keyFactory2.generatePublic(publicKeySpec2));
        byte[] decryptedMessageBytes = encryptCipher2.doFinal(signedMessageBytes);
        String stringHash = new String(decryptedMessageBytes);

        //Compare client hash data with server hash data
        if(rawLicenseTextHash.equals(stringHash)) {
            writeToFile(signedMessageBytes, "license.txt");
            System.out.println("Client -- Succeed. The license file content is secured and signed by the server.");
        }
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

    public static void writeToFile(byte[] str1, String outputFile){

        File file = new File(outputFile);
        try (FileOutputStream outputStream = new FileOutputStream(file)) {
            outputStream.write(str1);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public static byte[] readAsByte(String fileName) {
        try {
            byte[] bytes = Files.readAllBytes(Paths.get(fileName));
            return bytes;
        }
        catch (IOException e) {
            return null;
        }
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
