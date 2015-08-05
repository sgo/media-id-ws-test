package be.persgroep.mediaid;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.SystemDefaultRoutePlanner;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;

import java.io.IOException;
import java.net.ProxySelector;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Map;

import static com.google.common.collect.Sets.newHashSet;
import static org.junit.Assert.assertEquals;

/**
 * How to run:
 * - specify the url for the key store holding your media-id client certificate (e.g: file:///tmp/client-certs.jks)
 * -- to convert a PEM file into a key store use the following commands:
 * --- $ openssl pkcs12 -export -in client.pem -inkey client.pem -name client > client.p12
 * --- $ keytool -importkeystore -srckeystore client.p12 -destkeystore client-certs.jks -srcstoretype pkcs12
 * - specify the password required to access your key store
 * - specify the url for the trust store holding the certificate authority certificates (e.g: file://$JAVA_HOME/jre/lib/security/cacerts)
 * -- you may want to use a trust store from Java 7 or 8 as the certificates bundled with Java 6 may have expired
 * - specify the password required to access your trust store (default is changeit)
 * - configure this project to run with Java 7 or 8 (the test should pass)
 * - configure this project to run with Java 6 (the test should fail with javax.net.ssl.SSLHandshakeException: Received fatal alert: handshake_failure)
 * - feel free to enable Java's SSL debug logging using the jvm property -Djavax.net.debug=ssl
 */
public class WebServiceTest {
    private static Logger logger = LoggerFactory.getLogger(WebServiceTest.class);

    private String keyStoreUrl = "???";
    private String keyStoreType = "JKS";
    private String keyStorePass = "123456";
    private String trustStoreUrl = "???";
    private String trustStorePass = "changeit";
    private String mediaIdServerUrl = "https://service.media-id.be:8443/";

    private CloseableHttpClient httpClient;

    @Before
    public void setup() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {
        if(keyStoreUrl.equals("???")) throw new RuntimeException("Specify a key store!");
        if(trustStoreUrl.equals("???")) throw new RuntimeException("Specify a trust store!");

        KeyStoreContext keyStoreContext = new KeyStoreContext(new UrlResource(keyStoreUrl), keyStoreType, keyStorePass.toCharArray());
        KeyStoreContext trustStoreContext = new KeyStoreContext(new UrlResource(trustStoreUrl), "JKS", trustStorePass.toCharArray());

        httpClient = HttpClients.custom()
                .setRoutePlanner(new SystemDefaultRoutePlanner(ProxySelector.getDefault()))
                .setDefaultRequestConfig(
                        RequestConfig.custom()
                                .setConnectionRequestTimeout(120000)
                                .setConnectTimeout(120000)
                                .setSocketTimeout(120000)
                                .build()
                )
                .useSystemProperties()
                .setSSLSocketFactory(new SSLConnectionSocketFactory(
                        SSLContexts.custom()
                                .loadKeyMaterial(keyStoreContext.toKeyStore(), keyStoreContext.getPassword())
                                .loadTrustMaterial(trustStoreContext.toKeyStore(), new TrustSelfSignedStrategy())
                                .build()
                )).build();
    }

    @After
    public void cleanup() throws IOException {
        httpClient.close();
    }

    @Test
    public void test() throws IOException {
        HttpGet request = new HttpGet(mediaIdServerUrl + "users/new");
        request.setHeader("Accept", "application/json");

        Map response = toMap(httpClient.execute(request).getEntity());

        assertEquals(newHashSet("children"), response.keySet());
        assertEquals(newHashSet(
                "email",
                "firstname",
                "lastname",
                "street",
                "number",
                "bus",
                "postalCode",
                "city",
                "country",
                "state",
                "dateOfBirth",
                "gender",
                "mobilePhone",
                "language",
                "auth"
        ), ((Map)response.get("children")).keySet());
    }

    private Map toMap(HttpEntity request) throws IOException {
        try {
            Map response = new ObjectMapper().readValue(request.getContent(), Map.class);
            logger.info("Received response:\n\n" + response);
            return response;
        } finally {
            request.getContent().close();
        }
    }

    public static class KeyStoreContext {
        private Resource resource;
        private String type;
        private char[] password;

        public KeyStoreContext(Resource resource, String type, char[] password) {
            this.resource = resource;
            this.type = type;
            this.password = password;
        }

        public KeyStore toKeyStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
            KeyStore ks = KeyStore.getInstance(type);
            ks.load(resource.getInputStream(), password);
            return ks;
        }

        public char[] getPassword() {
            return password;
        }
    }

}
