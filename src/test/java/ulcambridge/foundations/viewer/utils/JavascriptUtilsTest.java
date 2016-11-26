package ulcambridge.foundations.viewer.utils;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.*;
import static ulcambridge.foundations.viewer.utils.JavascriptUtils.createJavascriptString;

public class JavascriptUtilsTest {

    @Test
    public void testCreateJavascriptString1() {
        assertThat("\"abc\"", equalTo(createJavascriptString("abc")));
    }

    @Test
    public void testCreateJavascriptString2() {
        assertThat("\"foo\\\"bar\"",
                   equalTo(createJavascriptString("foo\"bar")));
    }
}
