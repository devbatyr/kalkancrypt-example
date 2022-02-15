package kz.ups.iso20022authorization.service;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;


public class XmlSignDocumentResolver extends ResourceResolverSpi {

    private final String expression = String.format("//*[local-name()='%s']", "Document");


    private Document doc;

    public XmlSignDocumentResolver(Document doc) {
        this.doc = doc;
    }

    @Override
    public XMLSignatureInput engineResolveURI(ResourceResolverContext context) {
        Node selectedElem = null;
        if (null == context.uriToResolve && doc != null) {
            NodeList documentNodes;
            XPath xpath = XPathFactory.newInstance().newXPath();
            try {
                documentNodes = (NodeList) xpath.evaluate(expression, doc, XPathConstants.NODESET);
            } catch (Exception e) {
                throw new SecurityException("Error occurred in document resolver:", e);
            }
            selectedElem = documentNodes.item(0);
            if (selectedElem == null) {
                return null;
            }
            XMLSignatureInput result = new XMLSignatureInput(selectedElem);
            result.setSecureValidation(context.secureValidation);
            result.setExcludeComments(true);
            result.setMIMEType("text/xml");
            result.setSourceURI(null);
            return result;
        }
        return null;
    }

    @Override
    public boolean engineCanResolveURI(ResourceResolverContext context) {
        return null == context.uriToResolve && doc != null;
    }

}