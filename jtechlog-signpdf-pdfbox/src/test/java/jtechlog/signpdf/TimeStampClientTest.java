package jtechlog.signpdf;


import org.junit.Test;

import java.security.MessageDigest;
import java.security.Security;

public class TimeStampClientTest {

    @Test
    public void testTimestamp() throws Exception {
        // Given
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        MessageDigest mda = MessageDigest.getInstance("SHA-256", "BC");
        byte [] digest = mda.digest("jtechlog".getBytes());

        // When
        TimeStampClient timeStampClient = new TimeStampClient("http://www.netlock.hu/timestamp.cgi", null, null);
        timeStampClient.stamp(digest);
    }
}
