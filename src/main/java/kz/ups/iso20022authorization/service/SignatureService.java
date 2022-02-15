package kz.ups.iso20022authorization.service;

import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.xmldsig.KncaXS;
import kz.ups.iso20022authorization.exception.SwSignatureException;
import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.encryption.XMLCipherParameters;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
public class SignatureService {

    @Value("${signature.cert.path}")
    private String certPath;
    @Value("${signature.key}")
    private String key;


    public static Base64.Decoder BASE_64_DECODER = Base64.getDecoder();

    private static final String SECUREMENT_ACTION_TRANSFORMER_EXCLUSION = "AppHdr";
    private static final String SECUREMENT_ACTION_EXCLUSION = "Document";
    private static final String SECUREMENT_ACTION_SEPARATOR = " | ";
    private static final String EXPRESSION;
    private static final String TRANSFORM_METHOD_ALG = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private static final String SIGNAUTRE_CANONICALIZATION_METHOD_ALG = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private static final String SIGNAUTRE_EXCLUSION_TRANSFORMER = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String SIGNATURE_LOCAL_NAME = "Signature";

    public static final QName BAH_NAME = new QName("urn:iso:std:iso:20022:tech:xsd:head.001.001.01", SECUREMENT_ACTION_TRANSFORMER_EXCLUSION);
    private static final QName WS_SECURITY_NAME = new QName("urn:iso:std:iso:20022:tech:xsd:head.001.001.01", "Sgntr");
    private static final Set<String> securementActionSet = new HashSet<>(Arrays.asList(SECUREMENT_ACTION_TRANSFORMER_EXCLUSION, "KeyInfo", SECUREMENT_ACTION_EXCLUSION));


    public boolean validateSignature(String body) throws SwSignatureException {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
            Document document = documentBuilder.parse(new InputSource(new StringReader(body)));

            Element signatureElementInMessage = (Element) document.getElementsByTagNameNS(DS_NS, SIGNATURE_LOCAL_NAME).item(0);
            XMLSignature signature = new XMLSignature(signatureElementInMessage, document.getBaseURI(), false);
            signature.addResourceResolver(new XmlSignDocumentResolver(document));
            signature.addResourceResolver(new XmlSignBAHResolver());

            KeyInfo ki = signature.getKeyInfo();
            X509Certificate cert = ki.getX509Certificate();

            return isValidSignatureValue(signature, cert);
        } catch (SAXException | IOException |
                ParserConfigurationException e) {
            log.error("Error while parsing xml ", e);
            throw new SwSignatureException("Error parsing xml " + e.getMessage());
        } catch (
                Exception e) {
            log.error("Validation error", e);
            throw new SwSignatureException("Signature Validation error, " + e.getMessage());
        }
    }


    private boolean isValidSignatureValue(XMLSignature signature, X509Certificate cert) throws XMLSignatureException {
        boolean result = signature.checkSignatureValue(cert);
        log.debug("Signature verification status is {}", result);
        return result;
    }


    static {
        Provider provider = new KalkanProvider();
        Security.removeProvider(KalkanProvider.PROVIDER_NAME);
        Security.addProvider(provider);
        KncaXS.loadXMLSecurity();


        org.apache.xml.security.Init.init();
        StringBuilder securementActionBuffer = new StringBuilder();
        for (String securementAction : securementActionSet) {
            securementActionBuffer.append(String.format("//*[local-name()='%s']", securementAction));
            securementActionBuffer.append(String.format("%s", SECUREMENT_ACTION_SEPARATOR));
        }
        String returnValue = securementActionBuffer.toString();
        EXPRESSION = returnValue.substring(0, returnValue.length() - SECUREMENT_ACTION_SEPARATOR.length());
    }

    public String sign(String xml) throws SwSignatureException {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
            final Document doc = documentBuilder.parse(new InputSource(new StringReader(xml)));

            Element sgntrElement = addSignatureElementToXml(doc);
            InputStream inputStream;
            inputStream = AccessController.doPrivileged((PrivilegedExceptionAction<InputStream>) () -> (InputStream) new FileInputStream(getOwnPrivateKeyPath()));
            String keystorepassFromVault = getPrivateKeyPassword();

            KeyStore store = KeyStore.getInstance("PKCS12", KalkanProvider.PROVIDER_NAME);
            store.load(inputStream, keystorepassFromVault.toCharArray());
            Enumeration<String> als = store.aliases();
            String alias = null;
            while (als.hasMoreElements()) {
                alias = als.nextElement();
            }
            final X509Certificate x509Certificate = (X509Certificate) store.getCertificate(alias);

            final String signMethod;
            final String digestMethod;
            String sigAlgOid = x509Certificate.getSigAlgOID();
            if (sigAlgOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
                signMethod = Constants.MoreAlgorithmsSpecNS + "rsa-sha1";
                digestMethod = Constants.MoreAlgorithmsSpecNS + "sha1";
            } else if (sigAlgOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
                signMethod = Constants.MoreAlgorithmsSpecNS + "rsa-sha256";
                digestMethod = XMLCipherParameters.SHA256;
            } else {
                signMethod = Constants.MoreAlgorithmsSpecNS + "gost34310-gost34311";
                digestMethod = Constants.MoreAlgorithmsSpecNS + "gost34311";
            }

            final XMLSignature xmlSignature = new XMLSignature(doc,
                    BAH_NAME.getNamespaceURI(),
                    signMethod,
                    SIGNAUTRE_CANONICALIZATION_METHOD_ALG);
            sgntrElement.appendChild(xmlSignature.getElement());

            xmlSignature.addResourceResolver(new XmlSignBAHResolver());
            xmlSignature.addResourceResolver(new XmlSignDocumentResolver(doc));
            xmlSignature.addKeyInfo(x509Certificate);

            prepareTransform(doc, digestMethod, xmlSignature);
            sign(keystorepassFromVault, store, alias, xmlSignature);
            return getResult(doc);
        } catch (Exception e) {
            log.error("Error while sign xml", e);
            throw new SwSignatureException("Error while trying to sign response");
        }
    }

    private String getPrivateKeyPassword() {
        return key;
    }

    private String getOwnPrivateKeyPath() {
        return certPath;
    }

    private void sign(String keystorepassFromVault, KeyStore store, String alias, XMLSignature xmlSignature) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, XMLSignatureException {
        final PrivateKey privateKey = (PrivateKey) store.getKey(alias, keystorepassFromVault.toCharArray());
        xmlSignature.sign(privateKey);
    }

    private String getResult(Document doc) throws TransformerException, IOException {
        StringWriter os = new StringWriter();
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));
        os.close();
        return os.toString();
    }

    private void prepareTransform(Document doc, String digestMethod, XMLSignature xmlSignature) throws XPathExpressionException, TransformationException, XMLSignatureException {
        XPath xpath = XPathFactory.newInstance().newXPath();
        NodeList elementsToSign = (NodeList) xpath.evaluate(EXPRESSION, doc, XPathConstants.NODESET);
        for (int i = 0; i < elementsToSign.getLength(); i++) {
            Element elementToSign = (Element) elementsToSign.item(i);
            String elementName = elementToSign.getLocalName();
            String id = UUID.randomUUID().toString();
            Transforms transforms = getSecurementTransformer(doc);
            if (SECUREMENT_ACTION_TRANSFORMER_EXCLUSION.equals(elementName)) {
                transforms.addTransform(SIGNAUTRE_EXCLUSION_TRANSFORMER);
                transforms.addTransform(TRANSFORM_METHOD_ALG);
                xmlSignature.addDocument("", transforms, digestMethod);
            } else if (SECUREMENT_ACTION_EXCLUSION.equals(elementName)) {
                transforms.addTransform(TRANSFORM_METHOD_ALG);
                xmlSignature.addDocument(null, transforms, digestMethod);
            } else {
                transforms.addTransform(TRANSFORM_METHOD_ALG);
                elementToSign.setAttributeNS(null, "Id", id);
                elementToSign.setIdAttributeNS(null, "Id", true);
                xmlSignature.addDocument("#" + id, transforms, digestMethod);
            }
        }
    }

    private Element addSignatureElementToXml(Document doc) throws SwSignatureException {
        final NodeList bahNodes = doc.getElementsByTagNameNS(BAH_NAME.getNamespaceURI(), BAH_NAME.getLocalPart());
        if (bahNodes.getLength() == 0) {
            log.error("No BAH element is provided in request");
            throw new SwSignatureException("No BAH element is provided in request");
        }

        Element bahElement = (Element) bahNodes.item(0);
        Element sgntrElement = doc.createElementNS(WS_SECURITY_NAME.getNamespaceURI(), WS_SECURITY_NAME.getLocalPart());

        sgntrElement.setPrefix(bahElement.getPrefix());
        bahElement.appendChild(sgntrElement);
        return sgntrElement;
    }

    private Transforms getSecurementTransformer(Document envelopeAsDocument) {
        return new Transforms(envelopeAsDocument);
    }
}