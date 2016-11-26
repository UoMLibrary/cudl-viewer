package ulcambridge.foundations.viewer.utils;

import org.apache.commons.io.output.StringBuilderWriter;
import org.codehaus.jackson.JsonFactory;
import org.codehaus.jackson.JsonGenerator;

import java.io.IOException;
import java.io.UncheckedIOException;

public final class JavascriptUtils {
    private static final JsonFactory JSON_FACTORY = new JsonFactory();

    /**
     * Create a string in Javascript syntax containing {@code value}.
     *
     * <p>For example:
     * <pre>{@code
     * "\"abc\"".equals(createJavascriptString("abc")) // true
     * "\"foo\\\"bar\"".equals(createJavascriptString("foo\"bar")) // true
     * }</pre>
     */
    public static String createJavascriptString(String value) {
        StringBuilderWriter writer = new StringBuilderWriter(value.length() + 2);

        try {
            JsonGenerator generator = JSON_FACTORY.createJsonGenerator(writer);
            generator.writeString(value);
            generator.close();
        }
        catch(IOException e) {
            // Should never happen as we're not doing any IO (in memory streams)
            throw new UncheckedIOException("IO error on in-memory streams", e);
        }
        return writer.toString();
    }

    private JavascriptUtils() {
        throw new RuntimeException();
    }
}
