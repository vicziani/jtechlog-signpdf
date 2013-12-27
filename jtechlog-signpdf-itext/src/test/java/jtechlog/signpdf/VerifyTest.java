package jtechlog.signpdf;

import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.CertificateInfo;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.SignaturePermissions;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class VerifyTest {

    @Test
    public void testT() throws Exception {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        verifySignatures("D:\\projects\\jtechlog-signpdf\\jtechlog-signpdf-pdfbox-stolen\\target\\test-classes\\jtechlog_signed.pdf");
    }

    public SignaturePermissions inspectSignature(

    AcroFields fields, String name, SignaturePermissions perms)
            throws GeneralSecurityException, IOException {
        List<AcroFields.FieldPosition> fps = fields.getFieldPositions(name);
    if (fps != null && fps.size() > 0) {
        AcroFields.FieldPosition fp = fps.get(0);
        Rectangle pos = fp.position;
        if (pos.getWidth() == 0 || pos.getHeight() == 0) {
            System.out.println("Invisible signature");
        }
        else {
            System.out.println(String.format(
                    "Field on page %s; llx: %s, lly: %s, urx: %s; ury: %s", fp.page,
                    pos.getLeft(), pos.getBottom(), pos.getRight(), pos.getTop()));
        }
    }
    PdfPKCS7 pkcs7 = verifySignature(fields, name);
    System.out.println("Digest algorithm: " + pkcs7.getHashAlgorithm());
    System.out.println("Encryption algorithm: " + pkcs7.getEncryptionAlgorithm());
    System.out.println("Filter subtype: " + pkcs7.getFilterSubtype());
    X509Certificate cert = (X509Certificate) pkcs7.getSigningCertificate();
    System.out.println("Name of the signer: " +
            CertificateInfo.getSubjectFields(cert).getField("CN"));
    if (pkcs7.getSignName() != null)
            System.out.println("Alternative name of the signer: "
            + pkcs7.getSignName());
    SimpleDateFormat date_format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS");
    System.out.println("Signed on: " +
            date_format.format(pkcs7.getSignDate().getTime()));
    if (pkcs7.getTimeStampDate() != null) {
        System.out.println("TimeStamp: " +
                date_format.format(pkcs7.getTimeStampDate().getTime()));
        TimeStampToken ts = pkcs7.getTimeStampToken();
        System.out.println("TimeStamp service: " + ts.getTimeStampInfo().getTsa());
        System.out.println("TimeStamp verified? "+ pkcs7.verifyTimestampImprint());
    }
    System.out.println("Location: " + pkcs7.getLocation());
    System.out.println("Reason: " + pkcs7.getReason());
    PdfDictionary sigDict = fields.getSignatureDictionary(name);
    PdfString contact = sigDict.getAsString(PdfName.CONTACTINFO);
    if (contact != null)
            System.out.println("Contact info: " + contact);
    perms = new SignaturePermissions(sigDict, perms);
    System.out.println("Signature type: " +
            (perms.isCertification() ? "certification" : "approval"));
    System.out.println("Filling out fields allowed: " +
            perms.isFillInAllowed());
    System.out.println("Adding annotations allowed: " +
            perms.isAnnotationsAllowed());
    for (SignaturePermissions.FieldLock lock : perms.getFieldLocks()) {
        System.out.println("Lock: " + lock.toString());
    }
    return perms;
}

    public PdfPKCS7 verifySignature(AcroFields fields, String name)
            throws GeneralSecurityException, IOException {
        System.out.println("Signature covers whole document: "
                + fields.signatureCoversWholeDocument(name));
        System.out.println("Document revision: " + fields.getRevision(name)
                + " of " + fields.getTotalRevisions());
        PdfPKCS7 pkcs7 = fields.verifySignature(name);
        System.out.println("Integrity check OK? " + pkcs7.verify());
        return pkcs7;
    }

    public void verifySignatures(String path)
            throws IOException, GeneralSecurityException {
        System.out.println(path);
        PdfReader reader = new PdfReader(path);

        PdfDictionary catalog = reader.getCatalog();
        int l = reader.getCertificationLevel();
        int c = reader.getCryptoMode();
        Map i = reader.getInfo();
        byte[] m = reader.getMetadata();

        AcroFields fields = reader.getAcroFields();

        ArrayList<String> names = fields.getSignatureNames();
        for (String name : names) {
            System.out.println("===== " + name + " =====");
            // verifySignature(fields, name);
            inspectSignature(fields, name, null);
        }
        System.out.println();
    }
}