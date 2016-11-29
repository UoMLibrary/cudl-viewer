package ulcambridge.foundations.viewer.authentication.distributed;

/**
 * Thrown when an attemp is made to create a JWT with a lifetime that is not
 * allowed. Perhaps too long, or in the future, etc.
 */
public class IllegalLifetimeTokenException extends TokenException {
    public IllegalLifetimeTokenException() {
    }

    public IllegalLifetimeTokenException(String s) {
        super(s);
    }

    public IllegalLifetimeTokenException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public IllegalLifetimeTokenException(Throwable throwable) {
        super(throwable);
    }
}
