# Verifier for PDF-documents published by egov.kz

This is a just sample kotlin-script to extract data from QR-codes, verify signature from extracted XML and validate its certificate by current date. I wrote it to demonstrate why their signed data make me cry.

NB: Believe me, my coding style is far better than you can see here :)

Dependencies:

```
<dependencies>
    <dependency>
        <groupId>com.google.zxing</groupId>
        <artifactId>core</artifactId>
        <version>3.3.0</version>
    </dependency>
    <dependency>
        <groupId>org.apache.pdfbox</groupId>
        <artifactId>pdfbox</artifactId>
        <version>2.0.5</version>
    </dependency>
    <dependency>
        <groupId>com.google.zxing</groupId>
        <artifactId>javase</artifactId>
        <version>3.3.0</version>
    </dependency>
    <dependency>
        <groupId>kz.gov.pki.kalkan</groupId>
        <artifactId>xmldsig</artifactId>
        <version>0.0.1-SNAPSHOT</version>
    </dependency>
    <dependency>
        <groupId>org.jetbrains.kotlin</groupId>
        <artifactId>kotlin-stdlib</artifactId>
        <version>1.1.2</version>
    </dependency>
    <dependency>
        <groupId>org.tukaani</groupId>
        <artifactId>xz</artifactId>
        <version>1.6</version>
    </dependency>
</dependencies>
```

You can find all these libraries in http://mvnrepository.com, except pki.gov.kz-libraries. I believe, you are able to find them by yourselves.

Usage is next:

kotlinc -cp core-3.3.0.jar:javase-3.3.0.jar:pdfbox-2.0.5.jar:kalkancrypt.jar:knca_xmldsig.jar:commons-logging-1.2.jar:xmlsec-1.5.8.jar:xz-1.6.jar -script edocverifier.kts "here_is_your.pdf"