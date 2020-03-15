
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.mycore.tools.restapi.client.v1.MyCoReRestAPIClient;
import org.mycore.tools.restapi.client.v1.MyCoReRestAPICredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@TestInstance(Lifecycle.PER_CLASS)
class UploadTest {
    Properties props;
    Path contentDir;
    String url, user, password;
    
    public static Logger LOGGER = LoggerFactory.getLogger(UploadTest.class);

    @BeforeAll
    protected void setup() throws Exception {
        props = new Properties();
        props.load(getClass().getResourceAsStream("/restapi.test.properties"));
        contentDir = Paths.get(props.getProperty("mcr.restclient.content.dir"));
        url = props.getProperty("mcr.restapi.baseurl");
        user = props.getProperty("mcr.restapi.user");
        password = props.getProperty("mcr.restapi.password");
    }

    @Test
    void readObjects() {
        try {
            URL url = new URL(props.getProperty("mcr.restapi.baseurl") + "/objects");
            try (InputStream in = url.openStream()) {
                String response = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                assertTrue(response.contains("<mycoreobjects"));
            }
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    void uploadObjectFromFile() {
        try {
            MyCoReRestAPICredentials credentials = new MyCoReRestAPICredentials(url, user, password);
            MyCoReRestAPIClient client = new MyCoReRestAPIClient(credentials);
            client.login();
            //upload mcrobject from file
            Path xmlFile = contentDir.resolve("mycore_object.xml");
            client.uploadMCRObject(xmlFile);
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    void uploadObjectFromString() {
        try {
            MyCoReRestAPICredentials credentials = new MyCoReRestAPICredentials(url, user, password);
            MyCoReRestAPIClient client = new MyCoReRestAPIClient(credentials);
            client.login();
            Path xmlFile = contentDir.resolve("mycore_object.xml");
            String xmlContent = Files.readString(xmlFile);
            String result = client.uploadMCRObject(xmlContent);
            LOGGER.info("Upload successful for: " + result);

        } catch (Exception e) {
            fail(e.getMessage());
        }
    }
    
    @Test
    void uploadDerivateFromString() {
        try {
            MyCoReRestAPICredentials credentials = new MyCoReRestAPICredentials(url, user, password);
            MyCoReRestAPIClient client = new MyCoReRestAPIClient(credentials);
            client.login();
            Path xmlFile = contentDir.resolve("mycore_object.xml");
            String mcrURL = client.uploadMCRObject(xmlFile);
            LOGGER.info("MyCoRe Object created: " + mcrURL);
            String mcrID = mcrURL.substring(mcrURL.lastIndexOf("/")+1);

            String derURL = client.createDerivate(mcrID, "derivate_types:fulltext");
            String derID = derURL.substring(derURL.lastIndexOf("/")+1);
            LOGGER.info("MyCoRe Derivate created: "+ derURL);
            
            String fileURL = client.uploadFile(mcrID, derID, "fulltext.txt", true, contentDir.resolve("fulltext.txt"));
            LOGGER.info("File uploaded: "+ fileURL);
            
        } catch (Exception e) {
            LOGGER.error("Error on Derivate upload", e);
            fail(e.getMessage());
        }
    }
    
    

    
}
