package ulcambridge.foundations.viewer.authentication.distributed;

public class TokenException extends Exception {
    public TokenException() {
    }

    public TokenException(String s) {
        super(s);
    }

    public TokenException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public TokenException(Throwable throwable) {
        super(throwable);
    }
}
