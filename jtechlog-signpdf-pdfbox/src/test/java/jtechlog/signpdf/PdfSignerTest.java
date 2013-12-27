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
}
