package jtechlog.signpdf;

import org.junit.Test;
import java.io.File;

public class PdfSignerTest {

    @Test
    public void testSignPdf() throws Exception {
        // Given
        PdfSigner pdfSigner = new PdfSigner();

        String root = new File(PdfSignerTest.class.getResource("/").toURI()).toString()
                + File.separator;

        // When
        pdfSigner.signPdf(
                root + "jtechlog.pdf",
                root + "jtechlog_signed.pdf");

        // Than
        System.out.println("Created: " + root + "jtechlog_signed.pdf");
    }

    /*PdfReader reader = new PdfReader(SIGNED2);
    AcroFields af = reader.getAcroFields();
    ArrayList<String> names = af.getSignatureNames();
    for (String name : names) {
        out.println("Signature name: " + name);
        out.println("Signature covers whole document: "
                + af.signatureCoversWholeDocument(name));
        out.println("Document revision: "
                + af.getRevision(name) + " of " + af.getTotalRevisions());
        PdfPKCS7 pk = af.verifySignature(name);
        Calendar cal = pk.getSignDate();
        Certificate[] pkc = pk.getCertificates();
        out.println("Subject: "
                + PdfPKCS7.getSubjectFields(pk.getSigningCertificate()));
        out.println("Revision modified: " + !pk.verify());
        Object fails[] = PdfPKCS7.verifyCertificates(pkc, ks, null, cal);
        if (fails == null)
            out.println("Certificates verified against the KeyStore");
        else
            out.println("Certificate failed: " + fails[1]);
    }           */
}
