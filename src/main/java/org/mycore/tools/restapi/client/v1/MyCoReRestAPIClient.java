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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.sql.Date;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.mycore.tools.restapi.client.util.MyCoReRestAPICredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * MyCoRe REST-API Client
 * 
 * @author Robert Stephan
 *
 */
public class MyCoReRestAPIClient {
    public static int HTTP_STATUSCODE_OK = 200;
    public static int HTTP_STATUSCODE_UNAUTHORIZED = 401;
    public static int HTTP_STATUSCODE_METHOD_NOT_ALLOWED = 405;
    public static String HTTP_HEADER_AUTHORIZATION = "Authorization";
    public static String HTTP_HEADER_ACCEPT = "Accept";

    private static DocumentBuilderFactory DBF;

    public static String KEY_ID = UUID.randomUUID().toString();
    public static KeyPair RSA_KEYS = null;
    static {
        DBF = DocumentBuilderFactory.newInstance();
        DBF.setNamespaceAware(true);
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(2048);

            RSA_KEYS = keyGenerator.genKeyPair();
        } catch (Exception e) {
            // do nothing
        }
    }
    private static final Logger LOGGER = LoggerFactory.getLogger(MyCoReRestAPIClient.class);

    private String error = "";
    private MyCoReRestAPICredentials credentials;

    String currentJWT = null; // JSON Web Token

    RSAKey currentServerPublicKey = null;

    HttpClient client = HttpClient.newHttpClient();

    public MyCoReRestAPIClient(MyCoReRestAPICredentials credentials) {
        this.credentials = credentials;
    }

    private boolean tryBasicAuthentication() {
        HttpClient httpClient = HttpClient.newBuilder().authenticator(new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(credentials.getUser(), credentials.getPassword().toCharArray());
            }
        }).build();

        try {
            HttpRequest loginGet = HttpRequest.newBuilder().GET()
                    .uri(URI.create(credentials.getRestAPIBaseURL() + "/auth/login")).build();
            HttpResponse<String> response = httpClient.send(loginGet, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == HTTP_STATUSCODE_METHOD_NOT_ALLOWED) {
                LOGGER.debug("GET not supported on " + loginGet.uri() + ": LTS 2017 is running");
                return false;
            }
            if (response.statusCode() == HTTP_STATUSCODE_OK) {
                storeSessionToken(response.headers());
                if (response.body() != null) {
                    LOGGER.debug(response.body());
                }
                return true;
            }
        } catch (IOException | InterruptedException e) {
            LOGGER.warn("Error while trying to login via GET on server.", e);
        }
        return false;
    }

    /**
     * return JWT Token for session
     * 
     * @param username
     * @param password
     * @return
     */
    public void login() {
        if (tryBasicAuthentication()) {
            return;
        }
        String loginToken = null;
        HttpClient client = HttpClient.newHttpClient();

        HttpRequest request = HttpRequest.newBuilder().GET().uri(URI.create(credentials.getRestAPIBaseURL() + "/auth"))
                .build();

        HttpResponse<String> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
            Optional<String> headerAuth = response.headers().firstValue("Authorization");
            if (headerAuth.isPresent() && headerAuth.get().startsWith("Bearer ")) {
                String bearer = headerAuth.get().substring(7);
                SignedJWT signedJWT = SignedJWT.parse(bearer);
                currentServerPublicKey = RSAKey.parse(signedJWT.getHeader().getJWK().toJSONObject());
                if (signedJWT.verify(new RSASSAVerifier(currentServerPublicKey))) {
                    LOGGER.debug("Key valid");

                    // create Login JWT (JSSON Web Token)
                    JWK jwkClientPublicKey = new RSAKey.Builder((RSAPublicKey) RSA_KEYS.getPublic()).keyID(KEY_ID)
                            .build();
                    LocalDateTime currentTime = LocalDateTime.now();
                    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer("MyCoRe REST API Client")
                            .jwtID(UUID.randomUUID().toString())
                            .expirationTime(Date.from(currentTime.plusMinutes(10).toInstant(ZoneOffset.UTC)))
                            .issueTime(Date.from(currentTime.toInstant(ZoneOffset.UTC)))
                            .notBeforeTime(Date.from(currentTime.minusMinutes(2).toInstant(ZoneOffset.UTC)))
                            .subject(credentials.getUser())
                            // additional claims/attributes about the subject can be added
                            // claims.setClaim("email", "mail@example.com");
                            // multi-valued claims work too and will end up as a JSON array
                            .claim("password", credentials.getPassword()).build();

                    JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).jwk(jwkClientPublicKey).build();
                    SignedJWT signedClientJWT = new SignedJWT(jwsHeader, claims);

                    signedClientJWT.sign(new RSASSASigner(RSA_KEYS.getPrivate()));
                    JWEObject jweObject = new JWEObject(
                            new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                                    .contentType("JWT").build(),
                            new Payload(signedClientJWT));
                    jweObject.encrypt(new RSAEncrypter(currentServerPublicKey.toPublicJWK()));
                    loginToken = jweObject.serialize();
                    LOGGER.debug("Login-Token:" + loginToken);
                }
            }
            if (response.body() != null) {
                LOGGER.debug(response.body());
            }

            /*
             * HttpPost postLogin = new HttpPost(restAPIBaseURL+"/auth"); String auth = username + ":" + password; byte[]
             * encodedAuth = Base64.getEncoder().encode( auth.getBytes(Charset.forName("ISO-8859-1"))); String authHeader =
             * "Basic " + new String(encodedAuth); request.setHeader(HttpHeaders.AUTHORIZATION, authHeader);
             */

            HttpRequest postLogin = HttpRequest.newBuilder().POST(BodyPublishers.noBody())
                    .uri(URI.create(credentials.getRestAPIBaseURL() + "/auth/login"))
                    .header(HTTP_HEADER_AUTHORIZATION, "Bearer " + loginToken).build();
            response = client.send(postLogin, BodyHandlers.ofString());
            storeSessionToken(response.headers());

            if (response.body() != null) {
                LOGGER.debug(response.body());
            }
        } catch (IOException | ParseException | JOSEException | InterruptedException e) {
            // TODO Auto-generated catch block
            LOGGER.error("Login failed", e);
            error = e.getMessage();
        }
    }

    public void renewSession(String data) {
        HttpClient client = HttpClient.newHttpClient();
        try {
            HttpRequest renewGet = HttpRequest.newBuilder()
                    .uri(URI.create(credentials.getRestAPIBaseURL() + "/auth/renew"))
                    .header(HTTP_HEADER_AUTHORIZATION, calcAuthorizationHeader())
                    .header(HTTP_HEADER_ACCEPT, "application/json, text/plain").build();
            LOGGER.debug(renewGet.headers().firstValue(HTTP_HEADER_AUTHORIZATION).orElse(""));
            HttpResponse<String> response = client.send(renewGet, BodyHandlers.ofString());
            if (response.statusCode() == HTTP_STATUSCODE_METHOD_NOT_ALLOWED) {
                LOGGER.debug("GET not supported on " + renewGet.uri() + ": LTS 2017 is running");
                HttpRequest postLogin = HttpRequest.newBuilder().POST(BodyPublishers.noBody())
                        .uri(URI.create(renewGet.uri().toString() + "?data=" + data))
                        .header(HTTP_HEADER_AUTHORIZATION, calcAuthorizationHeader()).build();
                response = client.send(postLogin, BodyHandlers.ofString());
            }
            storeSessionToken(response.headers());
            if (response.body() != null) {
                LOGGER.debug(response.body());
            }
        } catch (IOException | InterruptedException e) {
            LOGGER.error("renew session failed", e);
        }
    }

    public String calcAuthorizationHeader() {
        if (currentJWT == null) {
            return null;
        }
        if (JWSAlgorithm.Family.HMAC_SHA.contains(getCurrentJWT().getHeader().getAlgorithm())) {
            return "Bearer " + currentJWT;
        }
        Payload payload = new Payload(currentJWT);

        // Create JWS header with HS256 algorithm
        JWK jwkClientPublicKey = new RSAKey.Builder((RSAPublicKey) RSA_KEYS.getPublic()).keyID(KEY_ID).build();
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).jwk(jwkClientPublicKey).build();

        // Create JWS object
        JWSObject jwsObject = new JWSObject(jwsHeader, payload);
        try {
            jwsObject.sign(new RSASSASigner(RSA_KEYS.getPrivate()));
        } catch (JOSEException e) {
            LOGGER.error("Couldn't sign JWS object", e);
            return null;
        }
        return "Bearer " + jwsObject.serialize();
    }

    private void storeSessionToken(HttpHeaders headers) {
        Optional<String> headerAuth = headers.firstValue(HTTP_HEADER_AUTHORIZATION);
        if (headerAuth.isPresent() && headerAuth.get().startsWith("Bearer ")) {
            try {
                String jwt = headerAuth.get().substring(7);
                SignedJWT signedJWT = SignedJWT.parse(jwt);
                if (JWSAlgorithm.Family.HMAC_SHA.contains(signedJWT.getHeader().getAlgorithm())) {
                    currentJWT = jwt;
                    return;
                }
                RSAKey serverPublicKey = RSAKey.parse(signedJWT.getHeader().getJWK().toJSONObject());
                if (signedJWT.verify(new RSASSAVerifier(serverPublicKey))) {
                    currentJWT = jwt;
                }
            } catch (Exception e) {
                LOGGER.error("Failed to store session token", e);
            }
        }
    }

    public static void main(String[] args) {
        MyCoReRestAPIClient client = new MyCoReRestAPIClient(
                new MyCoReRestAPICredentials("http://localhost:8080/api/v1", "mycore", "alleswirdgut"));
        client.login();
        client.renewSession("Staying alive!");
    }

    public SignedJWT getCurrentJWT() {
        if (currentJWT != null) {
            try {
                return SignedJWT.parse(currentJWT);
            } catch (ParseException e) {
                LOGGER.error("Failed to get current JWT", e);
            }
        }
        return null;
    }

    public String uploadMCRObject(Path xmlFile) throws IOException, InterruptedException {
        URI uri = URI.create(credentials.getRestAPIBaseURL() + "/objects");
        TreeMap<String, String> data = new TreeMap<String, String>();
        data.put("md5", MCREncryptionHelper.createMD5Checksum(xmlFile));
        data.put("size", Long.toString(MCREncryptionHelper.getSize(xmlFile)));

        return executePostRequest(uri, data, xmlFile);
    }
    
    public String uploadMCRObject(String xmlContent) throws IOException, InterruptedException {
        URI uri = URI.create(credentials.getRestAPIBaseURL() + "/objects");
        TreeMap<String, String> data = new TreeMap<String, String>();
        data.put("md5", MCREncryptionHelper.createMD5Checksum(xmlContent));
        data.put("size", Long.toString(MCREncryptionHelper.getSize(xmlContent)));

        byte[] contents = xmlContent.getBytes(StandardCharsets.UTF_8);
        String fileName = "contents.xml";
        String mimeType = "application/xml";
        
        return executePostRequest(uri, data, contents, fileName, mimeType);
    }

    //String location =  "http://localhost:8080/rosdok/api/v1/objects/rosdok_document_0000000249";
    /**
     * 
     * @param mcrID
     * @param classification
     * @return the resolving url for the derivate object
     * @throws ClientProtocolException
     * @throws IOException
     * @throws InterruptedException 
     */
    public String createDerivate(String mcrID, String classifications) throws IOException, InterruptedException {
        URI uri = URI.create(credentials.getRestAPIBaseURL() + "/objects/" + mcrID + "/derivates");
        TreeMap<String, String> data = new TreeMap<String, String>();
        data.put("classifications", classifications);

        return executePostRequest(uri, data, null);
    }

    public String uploadFile(String mcrID, String derID, String path, boolean isMainDoc, Path file)
            throws IOException, InterruptedException {
        URI uri = URI
                .create(credentials.getRestAPIBaseURL() + "/objects/" + mcrID + "/derivates/" + derID + "/contents");
        SortedMap<String, String> data = createFileProperties(mcrID, derID, path, isMainDoc, file, false);

        return executePostRequest(uri, data, file);
    }

    public String deleteFiles(String mcrID, String derID) throws IOException, InterruptedException {
        URI uri = URI
                .create(credentials.getRestAPIBaseURL() + "/objects/" + mcrID + "/derivates/" + derID + "/contents");
        SortedMap<String, String> data = new TreeMap<String, String>();
        data.put("mcrObjectID", mcrID);
        data.put("mcrDerivateID", derID);

        return executeDeleteRequest(uri, data);
    }

    public String deleteDerivate(String mcrID, String derID) throws IOException, InterruptedException {
        URI uri = URI.create(credentials.getRestAPIBaseURL() + "/objects/" + mcrID + "/derivates/" + derID);
        SortedMap<String, String> data = new TreeMap<String, String>();
        data.put("mcrObjectID", mcrID);
        data.put("mcrDerivateID", derID);

        return executeDeleteRequest(uri, data);
    }

    /**
     * executes a HTTP Post request and returns the value of the Header "Location"
     * 
     * @param path - can be null
     * @return
     * @throws ClientProtocolException
     * @throws IOException
     * @throws InterruptedException 
     */
    public String executePostRequest(URI uri, SortedMap<String, String> data, Path path)
            throws IOException, InterruptedException {
        if(path!=null) {
        String mimeType = Files.probeContentType(path);
        byte[] contents = Files.readAllBytes(path);
        String fileName = path.getFileName().toString();
        
        return executePostRequest(uri, data, contents, fileName, mimeType);
        }
        else {
            return executePostRequest(uri, data, null, null, null);
        }
    }
    
    public String executePostRequest(URI uri, SortedMap<String, String> data, byte[] contents, String fileName, String mimeType)
            throws IOException, InterruptedException {
        String boundary = UUID.randomUUID().toString();
        HttpRequest.Builder httpPost = HttpRequest.newBuilder().POST(ofMimeMultipartData(data, contents, fileName, mimeType, boundary))
                .uri(uri);
        httpPost.header("Content-Type", "multipart/form-data;boundary=" + boundary);
        if (data.size() > 0) {
            httpPost.header("X-MyCoRe-RestAPI-Signature",
                    MCREncryptionHelper.generateSignatureFromProperties(data, RSA_KEYS.getPrivate()));
        }
        httpPost.header(HTTP_HEADER_AUTHORIZATION, calcAuthorizationHeader());

        return executeRequest(httpPost.build());
    }

    public String executeDeleteRequest(URI uri, SortedMap<String, String> data)
            throws IOException, InterruptedException {
        HttpRequest.Builder httpDelete = HttpRequest.newBuilder().DELETE().uri(uri);
        if (data.size() > 0) {
            httpDelete.header("X-MyCoRe-RestAPI-Signature",
                    MCREncryptionHelper.generateSignatureFromProperties(data, RSA_KEYS.getPrivate()));

        }
        httpDelete.header(HTTP_HEADER_AUTHORIZATION, calcAuthorizationHeader());

        return executeRequest(httpDelete.build());
    }

    public String executeRequest(HttpRequest request) throws IOException, InterruptedException {
        HttpResponse<InputStream> response = client.send(request, BodyHandlers.ofInputStream());
        storeSessionToken(response.headers());
        LOGGER.debug(Integer.toString(response.statusCode()));
        if (response.statusCode() == 201) {
            String go2 = response.headers().firstValue("Location").orElse("");
            LOGGER.debug("Location: " + go2);
            return go2;
        }
        if (response.statusCode() != 200) {
            return null;
        }
        return retrieveStringFromInputStream(response.body());

    }

    /**
     * 
     * @param httpclient
     * @param baseurl
     * @param mcrID
     * @param derID
     * @param fileData a Map of "path" in derivate and java.io.File object
     * @throws InterruptedException 
     * @throws ClientProtocolException
     * @throws IOException
     */
    public List<String> uploadFiles(String mcrID, String derID, Map<String, Path> fileData)
            throws IOException, InterruptedException {

        ArrayList<String> result = new ArrayList<String>();
        for (String path : fileData.keySet()) {
            String go2 = uploadFile(mcrID, derID, path, false, fileData.get(path));
            result.add(go2);
        }
        return result;
    }

    private static SortedMap<String, String> createFileProperties(String mcrID, String derID, String path,
            boolean isMainDoc, Path f, boolean unzip) {
        TreeMap<String, String> result = new TreeMap<String, String>();
        result.put("path", path);
        result.put("maindoc", Boolean.toString(isMainDoc));
        result.put("md5", MCREncryptionHelper.createMD5Checksum(f));
        result.put("size", Long.toString(MCREncryptionHelper.getSize(f)));
        result.put("mcrObjectID", mcrID);
        result.put("mcrDerivateID", derID);
        result.put("unzip", Boolean.toString(unzip));
        return result;
    }

    /**
     * 
     * @param baseurl
     * @param recordIndentifier
     * @return the MCRObject ID as String
     */
    public String findMCRObject(String searchKey, String value) {
        String url = credentials.getRestAPIBaseURL() + "/search?q=" + searchKey + ":" + value;
        try {
            URL theURL = new URL(url);
            InputStream is = theURL.openStream();
            DocumentBuilder dBuilder = DBF.newDocumentBuilder();
            Document doc = dBuilder.parse(is);
            is.close();
            Element eResult = (Element) doc.getDocumentElement().getElementsByTagName("result").item(0);
            int numFound = Integer.parseInt(eResult.getAttribute("numFound"));
            if (numFound == 0) {
                return null;
            }
            if (numFound == 1) {
                NodeList nl = eResult.getElementsByTagName("str");
                for (int i = 0; i < nl.getLength(); i++) {
                    Element e = (Element) nl.item(i);
                    {
                        if (e.getAttribute("name").equals("id")) {
                            return e.getTextContent();
                        }
                    }
                }
            }

        } catch (Exception e) {
            LOGGER.error("error on find MyCoRe object", e);
        }
        return null;
    }

    /**
     * 
     * @param baseurl
     * @param recordIndentifier
     * @return the MCRObject ID as String
     */
    public List<String> findDerivatesByClassification(String mcrid, String classification) {
        List<String> result = new ArrayList<>();
        String url = credentials.getRestAPIBaseURL() + "/objects/" + mcrid + "/derivates";
        try {
            URL theURL = new URL(url);
            try (InputStream is = theURL.openStream()) {
                DocumentBuilder dBuilder = DBF.newDocumentBuilder();
                Document doc = dBuilder.parse(is);
                NodeList nl = doc.getDocumentElement().getElementsByTagName("derobject");
                for (int i = 0; i < nl.getLength(); i++) {
                    Element eDerObject = (Element) nl.item(i);
                    if (eDerObject.hasAttribute("classifications")) {
                        List<String> classifications = Arrays
                                .asList(eDerObject.getAttribute("classifications").split("\\s"));
                        if (classifications.contains(classification)) {
                            result.add(eDerObject.getAttribute("ID"));
                        }
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.error("Failed to find derivate by label", e);
        }
        return result;
    }

    public String retrieveMCRID_waitIfNecessary(String searchKey, String value, int numberOfRepeats,
            int secondsToWait) {
        String mcrID = null;
        do {
            mcrID = findMCRObject(searchKey, value);
            if (mcrID == null) {
                LOGGER.debug("No MyCoRe Object found for " + searchKey + ": " + value + " -> waiting " + secondsToWait
                        + " seconds then going to try again");
                try {
                    TimeUnit.SECONDS.sleep(secondsToWait);
                } catch (InterruptedException e) {
                    //do nothing
                }
            }
            numberOfRepeats--;
        } while (numberOfRepeats > 0 && mcrID == null);
        return mcrID;
    }

    public void clean() {
        error = "";
    }

    public String getRestAPIBaseURL() {
        return credentials.getRestAPIBaseURL();
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public final String retrieveStringFromInputStream(InputStream is) throws IOException {

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nRead;
        byte[] data = new byte[1024];
        while ((nRead = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }

        buffer.flush();
        byte[] byteArray = buffer.toByteArray();

        return new String(byteArray, StandardCharsets.UTF_8);
    }

    public static BodyPublisher ofMimeMultipartData(Map<String, String> data, byte[] contents, String fileName, String mimeType, String boundary)
            throws IOException {
        var byteArrays = new ArrayList<byte[]>();
        byte[] separator = ("--" + boundary + "\r\nContent-Disposition: form-data; name=")
                .getBytes(StandardCharsets.UTF_8);
        for (Map.Entry<String, String> entry : data.entrySet()) {
            byteArrays.add(separator);
            byteArrays.add(("\"" + entry.getKey() + "\"\r\n\r\n" + entry.getValue() + "\r\n")
                    .getBytes(StandardCharsets.UTF_8));

        }
        if (contents != null) {
            byteArrays.add(separator);
            byteArrays.add(("\"" + "file" + "\"; filename=\"" + fileName + "\"\r\nContent-Type: " + mimeType
                    + "\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            byteArrays.add(contents);
            byteArrays.add("\r\n".getBytes(StandardCharsets.UTF_8));
        }

        byteArrays.add(("--" + boundary + "--").getBytes(StandardCharsets.UTF_8));
        return BodyPublishers.ofByteArrays(byteArrays);
    }
    
}
