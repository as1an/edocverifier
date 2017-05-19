import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.client.j2se.BufferedImageLuminanceSource
import com.google.zxing.common.HybridBinarizer
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.util.encoders.Base64
import kz.gov.pki.kalkan.xmldsig.KncaXS
import javax.imageio.ImageIO
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject
import org.apache.xml.security.signature.XMLSignature
import org.tukaani.xz.LZMAInputStream
import org.w3c.dom.Element
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.Security
import java.util.zip.ZipInputStream
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.stream.XMLInputFactory

try {
    val pdoc = PDDocument.load(File(args[0]))
    var elamount: Int = 0
    val partsMap = mutableMapOf<Int, String>()
    val baos = ByteArrayOutputStream()
    pdoc.pages.forEach { page ->
        val resources = page.resources
        val xobjnames = resources.xObjectNames
        for (xobj in xobjnames) {
            baos.reset()
            if (resources.isImageXObject(xobj)) {
                val image = (resources.getXObject(xobj) as PDImageXObject).image
                ImageIO.write(image, "png", baos)
                try {
                    val binaryBitmap = BinaryBitmap(HybridBinarizer(
                            BufferedImageLuminanceSource(
                                    ImageIO.read(ByteArrayInputStream(baos.toByteArray())))))
                    val qrCodeResult = MultiFormatReader().decode(binaryBitmap)
                    val xml = qrCodeResult.text
                    println("qrxml: $xml")
                    val xfac = XMLInputFactory.newFactory()
                    val xsr = try {
                        val sr = xfac.createXMLStreamReader(xml.byteInputStream(), "UTF-8")
                        sr.next()
                        sr
                    } catch(e: Exception) {
                        val sr = xfac.createXMLStreamReader(ByteArrayInputStream(Base64.decode(xml)), "UTF-8")
                        sr.next()
                        sr
                    }
                    var elnum: Int = 0
                    var eldata: String = ""
                    println(xsr.localName)
                    when (xsr.localName) {
                        "BarcodeElement" -> {
                            while (xsr.hasNext()) {
                                if (xsr.isStartElement) {
                                    when (xsr.localName) {
                                        "elementData" -> eldata = xsr.elementText
                                        "elementNumber" -> elnum = xsr.elementText.toInt()
                                        "elementsAmount" -> elamount = xsr.elementText.toInt()
                                    }
                                }
                                xsr.next()
                            }
                        }
                        "QRCodePayCheck" -> {
                            while (xsr.hasNext()) {
                                if (xsr.isStartElement) {
                                    when (xsr.localName) {
                                        "Data" -> eldata = xsr.elementText
                                        "Position" -> elnum = xsr.elementText.toInt()
                                        "TotalParts" -> elamount = xsr.elementText.toInt()
                                    }
                                }
                                xsr.next()
                            }
                        }
                    }
                    partsMap.put(elnum, eldata)
                } catch (e: Exception) {
//                        println("Ignore as not a payload. $e")
                }
            }
        }
    }
    if (elamount != partsMap.size) {
        throw IllegalArgumentException("Found ${partsMap.size} parts instead of $elamount")
    }
    baos.reset()
    for (entry in partsMap.toSortedMap()) {
        println(entry.value)
        baos.write(Base64.decode(entry.value))
    }
    val compressed = baos.toByteArray()
    if (compressed[0] == 0x50.toByte() && compressed[1] == 0x4B.toByte()) {
        ZipInputStream(ByteArrayInputStream(compressed)).use {
            baos.reset()
            it.nextEntry
            baos.write(it.readBytes())
        }
    } else {
        LZMAInputStream(ByteArrayInputStream(compressed)).use {
            baos.reset()
            baos.write(it.readBytes())
        }
    }
    val extracted = baos.toByteArray()
    println(String(extracted))
    Security.addProvider(KalkanProvider())
    KncaXS.loadXMLSecurity()
    val dbf = DocumentBuilderFactory.newInstance()
    dbf.setNamespaceAware(true)
    val db = dbf.newDocumentBuilder()
    val doc = db.parse(ByteArrayInputStream(extracted))
    val rootel = doc.firstChild as Element
    val dsnode = rootel.getElementsByTagName("digiSign")
    val signode = if (dsnode.length != 0) {
        val dsxml = Base64.decode(dsnode.item(0).textContent)
        println("digiSign: ${String(dsxml)}")
        val dsdoc = db.parse(ByteArrayInputStream(dsxml))
        (dsdoc.firstChild as Element).getElementsByTagName("ds:Signature")
    } else {
        rootel.getElementsByTagName("ds:Signature")
    }
    if (signode.length == 0) {
        throw IllegalArgumentException("There is no signature!")
    }
    if (signode.length > 1) {
        throw IllegalArgumentException("There is more than 1 signature!")
    }
    val sigel = signode.item(0) as Element
    val xsig = XMLSignature(sigel, "")
    val cert = xsig.keyInfo.x509Certificate
    println("Verification status: ${xsig.checkSignatureValue(cert)}")
    println(cert.subjectDN)
    cert.checkValidity()
} catch (e: Exception) {
    e.printStackTrace()
}
