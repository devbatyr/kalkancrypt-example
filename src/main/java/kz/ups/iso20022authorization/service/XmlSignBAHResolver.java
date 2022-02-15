/*
 * The document resolver to AppHdr resource if uri is "" in reference validation
 */

package kz.ups.iso20022authorization.service;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import static kz.ups.iso20022authorization.service.SignatureService.BAH_NAME;


public class XmlSignBAHResolver extends ResourceResolverSpi {


    @Override
    public XMLSignatureInput engineResolveURI(ResourceResolverContext context) {
        Document doc = context.attr.getOwnerElement().getOwnerDocument();
        Node selectedElem = null;
        if (context.uriToResolve.equals("")) {
            NodeList bahNodes = doc.getElementsByTagNameNS(BAH_NAME.getNamespaceURI(), BAH_NAME.getLocalPart());
            selectedElem = bahNodes.item(0);
            if (selectedElem == null) {
                return null;
            }
            XMLSignatureInput result = new XMLSignatureInput(selectedElem);
            result.setSecureValidation(context.secureValidation);
            result.setExcludeComments(true);
            result.setMIMEType("text/xml");
            result.setSourceURI(context.uriToResolve);
            return result;
        }
        return null;
    }

    @Override
    public boolean engineCanResolveURI(ResourceResolverContext context) {
        return null != context.uriToResolve && context.uriToResolve.equals("");
    }


}