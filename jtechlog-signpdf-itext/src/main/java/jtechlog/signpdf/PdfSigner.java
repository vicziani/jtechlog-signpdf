package jtechlog.signpdf;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class PdfSigner {

    private static final String PROVIDER_BC = "BC";

    private static final String PASSWORD = "storepass";

    private static final String KEYSTORE_TYPE_PKCS12 = "PKCS12";

    private static final String HASH_ALGORITHM_SHA256 = "SHA-256";

    private static final String KEYSTORE_LOCATION = "/jtechlog-netlock-test.p12";

    private static final String ALIAS = "netlock teszt aláíró tanúsítvány netlock kft. azonosítója";

    private static final String NETLOCK_TIMESTAMP_URL = "http://www.netlock.hu/timestamp.cgi";

    private static final int ESTIMATED_SIZE = 10000;

    private PrivateKey privateKey;

    private Certificate[] chain;

    public PdfSigner() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        try {
            KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE_PKCS12, PROVIDER_BC);
            InputStream input = PdfSigner.class.getResourceAsStream(KEYSTORE_LOCATION);

            keystore.load(input, PASSWORD.toCharArray());

            privateKey = (PrivateKey) keystore.getKey(ALIAS, PASSWORD.toCharArray());

            chain = keystore.getCertificateChain(ALIAS);
        } catch (KeyStoreException | NoSuchProviderException | IOException |
                NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
            throw new RuntimeException("Error while loading certificates and private key", e);
        }
    }

    public void signPdf(String src, String dest) {
        try {
            PdfReader reader = new PdfReader(src);
            FileOutputStream os = new FileOutputStream(dest);
            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');

            // appearance
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            appearance.setSignatureCreator("Istvan Viczian");
            appearance.setReason("JTechLog post");
            appearance.setLocation("JTechLog");

            appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);

            ExternalSignature es = new PrivateKeySignature(privateKey, HASH_ALGORITHM_SHA256, PROVIDER_BC);
            ExternalDigest digest = new BouncyCastleDigest();

            TSAClient tsc = new TSAClientBouncyCastle(
                    NETLOCK_TIMESTAMP_URL, null, null, ESTIMATED_SIZE, HASH_ALGORITHM_SHA256);

            MakeSignature.signDetached(appearance, digest, es, chain, null, null, tsc, 0, MakeSignature.CryptoStandard.CMS);

            stamper.close();
        } catch (IOException | DocumentException | GeneralSecurityException e) {
            throw new RuntimeException("Error while signing pdf", e);
        }
    }
}
