package org.mycore.tools.restapi.client;

import java.util.List;

import org.mycore.tools.restapi.client.util.MyCoReRestAPICredentials;
import org.mycore.tools.restapi.client.v2.MyCoReRestAPIClient;
import org.w3c.dom.Document;

public class SampleAppV2 {

    public void run() {
        MyCoReRestAPICredentials creds = new MyCoReRestAPICredentials("http://localhost:8080/skeleton/api/v2", "administrator", "****");
        MyCoReRestAPIClient client = new MyCoReRestAPIClient(creds);
        Document doc = client.receiveObject("skeleton_simpledoc_00000001");
        System.out.println(client.xmlDocument2String(doc));
        
        Document docObj = client.createObject(MyCoReRestAPIClient.EMPTY_OBJECT_XML);
        System.out.println(client.xmlDocument2String(docObj));
        
        Document docDer = client.createNewDerivate(docObj.getDocumentElement().getAttribute("ID"), 2, "hello.doc", List.of("derivate_types:thumbnail"), List.of("Ich bin das neue Derivat", "(en)I am the new derivate", "(ru)Я новый дериват"));
        System.out.println(client.xmlDocument2String(docDer));

        
    }
    
    public static void main(String... args) {
        SampleAppV2 app = new SampleAppV2();
        app.run();
    }
}
