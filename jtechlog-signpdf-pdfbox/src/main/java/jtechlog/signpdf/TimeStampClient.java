package jtechlog.signpdf;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;

public class TimeStampClient {

    private String url;

    private String tsaUsername;

    private String tsaPassword;

    public TimeStampClient(String url, String tsaUsername, String tsaPassword) {
        this.url = url;
        this.tsaUsername = tsaUsername;
        this.tsaPassword = tsaPassword;
    }

    public byte[] stamp(byte[] content) {
        OutputStream out;
        HttpURLConnection con;

        try {
            TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
            timeStampRequestGenerator.setCertReq(true);
            BigInteger now = BigInteger.valueOf(System.currentTimeMillis());
            TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA256, content, now);
            byte request[] = timeStampRequest.getEncoded();

            URL u = new URL(url);
            con = (HttpURLConnection) u.openConnection();
            con.setDoOutput(true);
            con.setDoInput(true);
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-type", "application/timestamp-query");

            if ((tsaUsername != null) && !tsaUsername.equals("")) {
                String userPassword = tsaUsername + ":" + tsaPassword;
                con.setRequestProperty("Authorization", "Basic " +
                        new String(Base64.encode(userPassword.getBytes())));
            }

            con.setRequestProperty("Content-length", String.valueOf(request.length));

            out = con.getOutputStream();
            out.write(request);
            out.flush();

            if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
                throw new IOException("Received HTTP error: " + con.getResponseCode() + " - " + con.getResponseMessage());
            }
            InputStream in = con.getInputStream();
            TimeStampResp resp = TimeStampResp.getInstance(new ASN1InputStream(in).readObject());
            TimeStampResponse response = new TimeStampResponse(resp);
            response.validate(timeStampRequest);

            if (response.getFailInfo()
                    != null) {
                resolveStatusCode(response.getFailInfo().intValue());

            }

            return response.getTimeStampToken().getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void resolveStatusCode(int statusCode) {
        switch (statusCode) {
            case 0: {
                throw new RuntimeException("unrecognized or unsupported Algorithm Identifier");
            }

            case 2: {
                throw new RuntimeException("transaction not permitted or supported");
            }

            case 5: {
                throw new RuntimeException("the data submitted has the wrong format");
            }

            case 14: {
                throw new RuntimeException("the TSA’s time source is not available");
            }

            case 15: {
                throw new RuntimeException("the requested TSA policy is not supported by the TSA");
            }
            case 16: {
                throw new RuntimeException("the requested extension is not supported by the TSA");
            }

            case 17: {
                throw new RuntimeException("the additional information requested could not be understood or is not available");
            }

            case 25: {
                throw new RuntimeException("the request cannot be handled due to system failure");
            }
        }
    }
}
