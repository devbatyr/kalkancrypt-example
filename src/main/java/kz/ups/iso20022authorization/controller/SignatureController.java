package kz.ups.iso20022authorization.controller;

import kz.ups.iso20022authorization.exception.SwSignatureException;
import kz.ups.iso20022authorization.service.SignatureService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SignatureController {
    private final SignatureService signatureService;

    @Autowired
    public SignatureController(SignatureService signatureService) {
        this.signatureService = signatureService;
    }

    @RequestMapping(value = "/sign", method = RequestMethod.POST, produces = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<String> sign(@RequestBody String body) throws Exception {
        try {
            String signed = new String(signatureService.sign(body));
            return new ResponseEntity<>(signed, HttpStatus.OK);
        } catch (SwSignatureException e) {
            return new ResponseEntity<>("Error while sign xml", HttpStatus.UNAUTHORIZED);
        }
    }

    @RequestMapping(value = "/validate", method = RequestMethod.POST, consumes = MediaType
            .APPLICATION_XML_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Boolean> validate(@RequestBody String body) {
        boolean result;
        try {
            result = signatureService.validateSignature(body);
        } catch (SwSignatureException e) {
            result = false;
        }
        return new ResponseEntity<>(result, result ? HttpStatus.OK : HttpStatus.UNAUTHORIZED);
    }

}
