package org.mycore.tools.restapi.client.v2;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.mycore.tools.restapi.client.util.MyCoReRestAPICredentials;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

public class MyCoReRestAPIClient {
    private MyCoReRestAPICredentials credentials;

    HttpClient client = null;

    public static final String EMPTY_OBJECT_XML = "" +
        "<mycoreobject ID=\"skeleton_simpledoc_00000001\">\r\n" +
        "  <structure />\r\n" +
        "  <metadata>\r\n" +
        "    <def.title class=\"MCRMetaLangText\" heritable=\"false\" notinherit=\"true\">\r\n" +
        "      <title inherited=\"0\" form=\"plain\">Meine erste Publikation</title>\r\n" +
        "    </def.title>\r\n" +
        "    <def.language class=\"MCRMetaClassification\" heritable=\"false\" notinherit=\"true\">\r\n" +
        "      <language inherited=\"0\" classid=\"rfc4646\" categid=\"en\"/>\r\n" +
        "    </def.language>" +
        "  </metadata>\r\n" +
        "  <service>\r\n" +
        "    <servstates class=\"MCRMetaClassification\">\r\n" +
        "      <servstate inherited=\"0\" classid=\"state\" categid=\"submitted\"/>\r\n" +
        "    </servstates>\r\n" +
        "  </service>\r\n" +
        "</mycoreobject>";

    private static DocumentBuilderFactory DBF = DocumentBuilderFactory.newInstance();

    private static TransformerFactory TF = TransformerFactory.newInstance();

    public MyCoReRestAPIClient(MyCoReRestAPICredentials credentials) {
        this.credentials = credentials;
        client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).authenticator(new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(credentials.getUser(), credentials.getPassword().toCharArray());
            }
        }).version(Version.HTTP_1_1).build();
    }

    public Document receiveObject(String id) {
        HttpRequest request = HttpRequest.newBuilder().GET().uri(URI.create(credentials.getRestAPIBaseURL()
            + "/objects/" + id)).build();
        try {
            HttpResponse<String> resp = client.send(request, BodyHandlers.ofString());
            DocumentBuilder builder = DBF.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(resp.body())));
            return doc;

        } catch (Exception e) {
            // TODO Logging
            e.printStackTrace();
        }
        return null;
    }

    /**
     * creates an empty MCRObject
     * The initial state (classification entry) is definied by the 2 properties:
     * MCR.Metadata.Service.State.Classification.ID (default "state")
     * MCR.Metadata.Service.State.Category.Default" (default "submitted").
     */
    public Document createObject(String xml) {
        try {
            HttpRequest request = HttpRequest.newBuilder().POST(BodyPublishers.ofString(xml))
                .uri(URI.create(credentials.getRestAPIBaseURL()
                    + "/objects"))
                .header("Content-Type", "application/xml").build();
            HttpResponse<String> resp = client.send(request, BodyHandlers.ofString());
            Optional<String> optLocation = resp.headers().firstValue("Location");
            if (optLocation.isPresent()) {
                String mcrId = optLocation.get().substring(optLocation.get().lastIndexOf("/") + 1);
                return receiveObject(mcrId);
            }

            return null;

        } catch (Exception e) {
            // TODO Logging
            e.printStackTrace();
        }
        return null;
    }

    public Document createNewDerivate(String mcrId) {
        try {
            HttpRequest request = HttpRequest.newBuilder().POST(BodyPublishers.ofString(""))
                .uri(URI.create(credentials.getRestAPIBaseURL()
                    + "/objects/" + mcrId + "/derivates"))
                .header("Content-Type", "application/xml").build();
            HttpResponse<String> resp = client.send(request, BodyHandlers.ofString());
            Optional<String> optLocation = resp.headers().firstValue("Location");
            if (optLocation.isPresent()) {
                String derId = optLocation.get().substring(optLocation.get().lastIndexOf("/") + 1);
                return receiveDerivate(mcrId, derId);
            }
        } catch (Exception e) {
            //TODO Logging
            e.printStackTrace();
        }
        return null;
    }
    
    public Document createNewDerivate(String mcrId, Integer order, String maindoc, List<String> classifications, List<String> titles) {
        ArrayList<Map.Entry<String,Object>> data = new ArrayList<>();
        if(order!=null) {
            data.add(Map.entry("order", order)); 
        }
        if(maindoc!=null) {
            data.add(Map.entry("maindoc", maindoc)); 
        }
        if(classifications!=null) {
            for(String c: classifications) {
                data.add(Map.entry("classification", c));
            }
        }
        if(titles!=null) {
            for(String t: titles) {
                data.add(Map.entry("title", t));
            }
        }
        
        
        try {
            HttpRequest request = HttpRequest.newBuilder().POST(ofFormData(data))
                .uri(URI.create(credentials.getRestAPIBaseURL()
                    + "/objects/" + mcrId + "/derivates"))
                .header("Content-Type", "application/x-www-form-urlencoded").build();
            HttpResponse<String> resp = client.send(request, BodyHandlers.ofString());
            Optional<String> optLocation = resp.headers().firstValue("Location");
            if (optLocation.isPresent()) {
                String derId = optLocation.get().substring(optLocation.get().lastIndexOf("/") + 1);
                return receiveDerivate(mcrId, derId);
            }
        } catch (Exception e) {
            //TODO Logging
            e.printStackTrace();
        }
        return null;
    }

    public Document receiveDerivate(String mcrId, String derId) {
        HttpRequest request = HttpRequest.newBuilder().GET().uri(URI.create(credentials.getRestAPIBaseURL()
            + "/objects/" + mcrId+"/derivates/"+derId)).build();
        try {
            HttpResponse<String> resp = client.send(request, BodyHandlers.ofString());
            DocumentBuilder builder = DBF.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(resp.body())));
            return doc;

        } catch (Exception e) {
            // TODO Logging
            e.printStackTrace();
        }
        return null;
    }

    public String xmlDocument2String(Document xml) {
        try {
            StringWriter writer = new StringWriter();
            Transformer transformer = TF.newTransformer();
            transformer.transform(new DOMSource(xml), new StreamResult(writer));
            return writer.toString();
        } catch (Exception e) {
            // TODO Logging
            e.printStackTrace();
        }
        return null;
    }

    // Sample: 'password=123&custom=secret&username=abc&ts=1570704369823'
    public static BodyPublisher ofFormData(List<Map.Entry<String, Object>> data) {
        var builder = new StringBuilder();
        for (Map.Entry<String, Object> entry : data) {
            if (builder.length() > 0) {
                builder.append("&");
            }
            builder.append(URLEncoder.encode(entry.getKey().toString(), StandardCharsets.UTF_8));
            builder.append("=");
            builder.append(URLEncoder.encode(entry.getValue().toString(), StandardCharsets.UTF_8));
        }
        return HttpRequest.BodyPublishers.ofString(builder.toString());
    }

    public static BodyPublisher ofMimeMultipartFormData(Map<Object, Object> data,
        String boundary) throws IOException {
        var byteArrays = new ArrayList<byte[]>();
        byte[] separator = ("--" + boundary + "\r\nContent-Disposition: form-data; name=")
            .getBytes(StandardCharsets.UTF_8);
        for (Map.Entry<Object, Object> entry : data.entrySet()) {
            byteArrays.add(separator);

            if (entry.getValue() instanceof Path) {
                var path = (Path) entry.getValue();
                String mimeType = Files.probeContentType(path);
                byteArrays.add(("\"" + entry.getKey() + "\"; filename=\"" + path.getFileName()
                    + "\"\r\nContent-Type: " + mimeType + "\r\n\r\n").getBytes(StandardCharsets.UTF_8));
                byteArrays.add(Files.readAllBytes(path));
                byteArrays.add("\r\n".getBytes(StandardCharsets.UTF_8));
            } else {
                byteArrays.add(("\"" + entry.getKey() + "\"\r\n\r\n" + entry.getValue() + "\r\n")
                    .getBytes(StandardCharsets.UTF_8));
            }
        }
        byteArrays.add(("--" + boundary + "--").getBytes(StandardCharsets.UTF_8));
        return BodyPublishers.ofByteArrays(byteArrays);
    }

}
