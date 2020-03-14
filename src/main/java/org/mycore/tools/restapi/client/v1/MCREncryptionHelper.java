/*
 * This file is part of ***  M y C o R e  ***
 * See http://www.mycore.de/ for details.
 *
 * MyCoRe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * MyCoRe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MyCoRe.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.mycore.tools.restapi.client.v1;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.SortedMap;
import java.util.TreeMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Key-generation with OpenSSL
 * ---------------------------
 *  > openssl genrsa -out clientPrivateKey.pem 1024 -des3
 *  > openssl genrsa -out serverPrivateKey.pem 1024 -des3
 *  
 *  > openssl rsa -in clientPrivateKey.pem -out clientPublicKey.key -pubout -outform der
 *  > openssl rsa -in serverPrivateKey.pem -out serverPublicKey.key -pubout -outform der
 *  
 *  > openssl pkcs8 -in clientPrivateKey.pem -out clientPrivateKey.p8 -outform der -nocrypt -topk8
 *  > openssl pkcs8 -in serverPrivateKey.pem -out serverPrivateKey.p8 -outform der -nocrypt -topk8
 *  
 *   
 * @author Robert Stephan
 *
 */
public class MCREncryptionHelper {
    private static final Logger LOGGER = LoggerFactory.getLogger(MCREncryptionHelper.class);

    //http://blog.axxg.de/java-verschluesselung-beispiel-quickstart/

    public static long getFileSize(Path f) {
        try {
            return Files.size(f);
        } catch (IOException e) {
            return -1;
        }
    }

    public static boolean verifyMD5Checksum(Path file, String testChecksum) {
        String fileHash = createMD5Checksum(file);
        return fileHash.equalsIgnoreCase(testChecksum);
    }

    /**
     * 
     * @param file
     * @param algorithmn: "SHA1" oder "MD5"
     * @return
     */
    public static String createMD5Checksum(Path file) {
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException nsae) {
            //does not happen, do nothing
        }
        byte[] data = new byte[1024];
        try (InputStream fis = Files.newInputStream(file)) {
            int read = 0;
            while ((read = fis.read(data)) != -1) {
                md5.update(data, 0, read);
            }
        } catch (IOException e) {
            LOGGER.error("Error creating MD5 checksum", e);
        }

        //output as hex
        return String.format("%032x", new BigInteger(1, md5.digest()));
    }

    public static final void createRSAKEYFiles(Path dir, String filenamePrefix) {
        // Datei
        try {
            // Verzeichnis anlegen
            Files.createDirectories(dir);

            // zufaelligen Key erzeugen
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
            keygen.initialize(1024);
            KeyPair keyPair = keygen.genKeyPair();

            // schluessel lesen
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Public Key sichern
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
            try (OutputStream fos = Files.newOutputStream(dir.resolve(filenamePrefix + ".public.key"))) {
                fos.write(x509EncodedKeySpec.getEncoded());
            }

            // Private Key sichern
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
            try (OutputStream fos = Files.newOutputStream(dir.resolve(filenamePrefix + ".private.key"))) {
                fos.write(pkcs8EncodedKeySpec.getEncoded());
            }

        } catch (Exception e) {
            LOGGER.error("Failed to create RSA key file", e);
        }
    }

    public static KeyPair genRSAKeys() {
        try {
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
            keygen.initialize(1024);
            return keygen.generateKeyPair();
        } catch (NoSuchAlgorithmException nsae) {
            //should not happen
            return null;
        }
    }

    public static String generateMessagesFromProperties(SortedMap<String, String> data) {
        StringWriter sw = new StringWriter();
        sw.append("{");
        for (String key : data.keySet()) {
            sw.append("\"").append(key).append("\"").append(":").append("\"").append(data.get(key)).append("\"")
                    .append(",");
        }
        String result = sw.toString();
        if (result.length() > 1) {
            result = result.substring(0, result.length() - 1);
        }
        result = result + "}";

        return result;
    }

    public static String generateSignatureFromProperties(SortedMap<String, String> data, PrivateKey privateKey) {
        String message = generateMessagesFromProperties(data);
        Signature signature = null;
        try {
            signature = Signature.getInstance("SHA1withRSA");
        } catch (NoSuchAlgorithmException nsae) {
            //should not happen;
        }

        try {
            signature.initSign(privateKey);
            signature.update(message.getBytes());
            byte[] sigBytes = signature.sign();
            return java.util.Base64.getEncoder().encodeToString(sigBytes);
        } catch (Exception e) {
            LOGGER.error("Failed to generate signature from properties", e);
            return null;
        }
    }

    public static boolean verifyPropertiesWithSignature(SortedMap<String, String> data, String base64Signature,
            PublicKey publicKey) {
        try {
            String message = generateMessagesFromProperties(data);

            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(publicKey);
            signature.update(message.getBytes());

            boolean x = signature.verify(java.util.Base64.getDecoder().decode(base64Signature));
            return x;

        } catch (Exception e) {
            LOGGER.error("Failed to verify properties with signature", e);
        }
        return false;
    }

    public static void main(String[] args) {
        SortedMap<String, String> data = new TreeMap<>();

        data.put("bravo", "Berta");
        data.put("alpha", "Anton");

        KeyPair kp = genRSAKeys();
        String sign = generateSignatureFromProperties(data, kp.getPrivate());

        System.out.println(verifyPropertiesWithSignature(data, sign, kp.getPublic()));
    }
}
