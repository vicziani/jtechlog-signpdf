package jtechlog.signpdf;


import org.apache.commons.io.IOUtils;
import org.apache.pdfbox.exceptions.COSVisitorException;
import org.apache.pdfbox.exceptions.SignatureException;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

public class PdfSigner implements SignatureInterface {

    private static final String PROVIDER_BC = "BC";

    private static final String PASSWORD = "storepass";

    private static final String KEYSTORE_TYPE_PKCS12 = "PKCS12";

    private static final String HASH_ALGORITHM_SHA256 = "SHA-256";

    private static final String KEYSTORE_LOCATION = "/jtechlog-netlock-test.p12";

    private static final String ALIAS = "netlock teszt aláíró tanúsítvány netlock kft. azonosítója";

    private static final String NETLOCK_TIMESTAMP_URL = "http://www.netlock.hu/timestamp.cgi";

    private static final int SIGNATURE_SIZE = 16000;

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
            File document = new File(src);
            File outputDocument = new File(dest);

            FileInputStream fis = new FileInputStream(document);
            FileOutputStream fos = new FileOutputStream(outputDocument);

            byte[] buffer = new byte[8 * 1024];
            int c;
            while ((c = fis.read(buffer)) != -1) {
                fos.write(buffer, 0, c);
            }
            fis.close();
            fis = new FileInputStream(outputDocument);

            PDDocument doc = PDDocument.load(document);

            PDSignature signature = new PDSignature();

            // default filter
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);

            // subfilter for basic and PAdES Part 2 signatures
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName("Istvan Viczian");
            signature.setReason("JTechLog post");
            signature.setLocation("JTechLog");

            // the signing date, needed for valid signature
            Calendar cal = Calendar.getInstance();
            signature.setSignDate(cal);

            SignatureOptions signatureOptions = new SignatureOptions();
            signatureOptions.setPreferedSignatureSize(SIGNATURE_SIZE);
            doc.addSignature(signature, this, signatureOptions);

            // write incremental (only for signing purpose)
            doc.saveIncremental(fis, fos);
        } catch (IOException | SignatureException | COSVisitorException e) {
            throw new RuntimeException("Error while signing pdf", e);
        }
    }

    @Override
    public byte[] sign(InputStream content) throws SignatureException, IOException {
        byte[] c = IOUtils.toByteArray(content);
        try {
            // general class for generating a pkcs7-signature message
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
                    .build(privateKey);

            gen.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder().setProvider("BC")
                                    .build())
                            .build(signer, (X509Certificate) chain[0]));

            Store certs = new JcaCertStore(Arrays.asList(chain));
            gen.addCertificates(certs);

            CMSTypedData msg = new CMSProcessableByteArray(c);
            // encapsulate false:  carrying a detached CMS signature.
            CMSSignedData signedData = gen.generate(msg, false);

            signedData = addTimestamp(signedData);

            // Transcode BER to DER
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            new DEROutputStream(baos).writeObject(signedData.toASN1Structure());
            return baos.toByteArray();

        } catch (Exception e) {
            // should be handled
            System.err.println("Error while creating pkcs7 signature.");
            e.printStackTrace();
        }
        throw new RuntimeException("Problem while preparing signature");

    }

    private static CMSSignedData addTimestamp(CMSSignedData signedData) throws Exception {
        Collection ss = signedData.getSignerInfos().getSigners();
        SignerInformation si = (SignerInformation) ss.iterator().next();

        TimeStampClient timeStampClient = new TimeStampClient(NETLOCK_TIMESTAMP_URL,
                null, null);

        // The hash of the sign
        MessageDigest mda = MessageDigest.getInstance(HASH_ALGORITHM_SHA256, PROVIDER_BC);

        byte[] digest = mda.digest(si.getSignature());

        byte[] ts = timeStampClient.stamp(digest);

        ASN1InputStream tempstream = new ASN1InputStream(new ByteArrayInputStream(ts));

        ASN1Sequence seq = (ASN1Sequence) tempstream.readObject();
        DERSet ds = new DERSet(seq);
        Attribute a = new Attribute(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14"), ds);

        ASN1EncodableVector dv = new ASN1EncodableVector();
        dv.add(a);
        AttributeTable at = new AttributeTable(dv);
        si = SignerInformation.replaceUnsignedAttributes(si, at);
        ss.clear();
        ss.add(si);
        SignerInformationStore sis = new SignerInformationStore(ss);

        signedData = CMSSignedData.replaceSigners(signedData, sis);
        return signedData;
    }

}
