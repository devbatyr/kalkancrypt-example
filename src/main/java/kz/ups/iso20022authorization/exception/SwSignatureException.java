package kz.ups.iso20022authorization.exception;

public class SwSignatureException extends Exception {
    public SwSignatureException() {
        super();
    }

    public SwSignatureException(String message) {
        super(message);
    }

    public SwSignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
