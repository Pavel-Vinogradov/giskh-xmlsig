package giskh_xmlsig

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/beevik/etree"
)

// SignXMLGIS подписывает XML документ для ГИС ЖКХ
func SignXMLGIS(xmlDoc []byte, cert *x509.Certificate, privateKey crypto.PrivateKey) ([]byte, error) {
	// 1. Парсим XML через etree (DOM)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlDoc); err != nil {
		return nil, fmt.Errorf("ошибка парсинга XML: %w", err)
	}

	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("пустой XML")
	}

	// 2. Проверяем, что это SOAP конверт
	if !isSOAPEnvelope(root) {
		return nil, fmt.Errorf("ожидается SOAP конверт")
	}

	// 3. Находим Body и добавляем wsu:Id если отсутствует
	body := findElement(root, "Body")
	if body == nil {
		return nil, fmt.Errorf("элемент Body не найден")
	}

	if body.SelectAttrValue("Id", "") == "" {
		body.CreateAttr("Id", "Body")
		body.CreateAttr("xmlns:wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
	}

	// 4. Создаем подпись
	signature := createGISSignatureElement(cert)

	// 5. Вычисляем дайджест Body с трансформациями
	transforms := []string{
		"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
		"http://www.w3.org/2001/10/xml-exc-c14n#",
	}

	bodyCanonical, err := CanonicalizeWithTransforms(body, transforms)
	if err != nil {
		return nil, fmt.Errorf("ошибка каноникализации Body: %w", err)
	}

	digestAlgorithm := "http://www.w3.org/2001/04/xmldsig-more#gostr3411"
	if !IsAlgorithmSupported(digestAlgorithm) {
		digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256"
	}

	digest, err := ComputeDigest([]byte(bodyCanonical), digestAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("ошибка вычисления дайджеста: %w", err)
	}

	// 6. Устанавливаем DigestValue
	digestValueElem := signature.FindElement(".//DigestValue")
	if digestValueElem != nil {
		digestValueElem.SetText(base64.StdEncoding.EncodeToString(digest))
	}

	// 7. Каноникализация SignedInfo
	signedInfo := signature.FindElement(".//SignedInfo")
	if signedInfo == nil {
		return nil, fmt.Errorf("SignedInfo не найден")
	}

	signedInfoCanonical, err := CanonicalizeEXC14N(signedInfo, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка каноникализации SignedInfo: %w", err)
	}

	// 8. Подписываем SignedInfo
	signatureAlgorithm := "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411"
	if !IsAlgorithmSupported(signatureAlgorithm) {
		signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	}

	signatureBytes, err := SignDataGOST([]byte(signedInfoCanonical), privateKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка подписания: %w", err)
	}

	// 9. Устанавливаем SignatureValue
	signatureValueElem := signature.FindElement(".//SignatureValue")
	if signatureValueElem != nil {
		signatureValueElem.SetText(base64.StdEncoding.EncodeToString(signatureBytes))
	}

	// 10. Добавляем информацию о сертификате в XAdES
	err = addXAdESCertificateInfo(signature, cert)
	if err != nil {
		return nil, fmt.Errorf("ошибка добавления XAdES: %w", err)
	}

	// 11. Вставляем подпись в SOAP Header
	header := findElement(root, "Header")
	if header == nil {
		header = root.CreateElement("Header")
		header.CreateAttr("xmlns:soapenv", "http://schemas.xmlsoap.org/soap/envelope/")
	}

	security := header.FindElement(".//Security")
	if security == nil {
		security = header.CreateElement("Security")
		security.CreateAttr("xmlns:wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	}

	security.AddChild(signature)

	// 12. Вывод XML
	var buf bytes.Buffer
	doc.WriteTo(&buf)

	return buf.Bytes(), nil
}

// isSOAPEnvelope проверяет, что корневой элемент является SOAP конвертом
func isSOAPEnvelope(root *etree.Element) bool {
	return root.Tag == "Envelope" &&
		(strings.Contains(root.SelectAttrValue("xmlns", ""), "soap") ||
			strings.Contains(root.SelectAttrValue("xmlns:soapenv", ""), "soap"))
}

// createGISSignatureElement создает структуру подписи для ГИС ЖКХ
func createGISSignatureElement(cert *x509.Certificate) *etree.Element {
	signature := etree.NewElement("ds:Signature")
	signature.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	signature.CreateAttr("Id", "xmldsig")

	signedInfo := signature.CreateElement("ds:SignedInfo")

	// CanonicalizationMethod
	canonMethod := signedInfo.CreateElement("ds:CanonicalizationMethod")
	canonMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")

	// SignatureMethod
	sigMethod := signedInfo.CreateElement("ds:SignatureMethod")
	sigMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411")

	// Reference
	ref := signedInfo.CreateElement("ds:Reference")
	ref.CreateAttr("URI", "#Body")

	// Transforms
	transforms := ref.CreateElement("ds:Transforms")
	transform1 := transforms.CreateElement("ds:Transform")
	transform1.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
	transform2 := transforms.CreateElement("ds:Transform")
	transform2.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")

	// DigestMethod
	digestMethod := ref.CreateElement("ds:DigestMethod")
	digestMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#gostr3411")

	// DigestValue (заполнится позже)
	digestValue := ref.CreateElement("ds:DigestValue")
	digestValue.SetText("")

	// SignatureValue (заполнится позже)
	signatureValue := signature.CreateElement("ds:SignatureValue")
	signatureValue.SetText("")

	// KeyInfo
	keyInfo := signature.CreateElement("ds:KeyInfo")
	x509Data := keyInfo.CreateElement("ds:X509Data")
	x509Cert := x509Data.CreateElement("ds:X509Certificate")
	x509Cert.SetText(base64.StdEncoding.EncodeToString(cert.Raw))

	// Object с XAdES
	object := signature.CreateElement("ds:Object")
	qualProps := object.CreateElement("xades:QualifyingProperties")
	qualProps.CreateAttr("Target", "#xmldsig")
	qualProps.CreateAttr("xmlns:xades", "http://uri.etsi.org/01903/v1.3.2#")

	signedProps := qualProps.CreateElement("xades:SignedProperties")
	signedProps.CreateAttr("Id", "signed-props")

	signedSigProps := signedProps.CreateElement("xades:SignedSignatureProperties")
	signingCert := signedSigProps.CreateElement("xades:SigningCertificate")
	certStruct := signingCert.CreateElement("xades:Cert")

	// CertDigest (заполнится позже)
	certDigest := certStruct.CreateElement("xades:CertDigest")
	dm := certDigest.CreateElement("ds:DigestMethod")
	dm.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#gostr3411")
	dv := certDigest.CreateElement("ds:DigestValue")
	dv.SetText("") // заполнится позже

	// IssuerSerial (заполнится позже)
	issuerSerial := certStruct.CreateElement("xades:IssuerSerial")
	issuerName := issuerSerial.CreateElement("ds:X509IssuerName")
	issuerName.SetText("") // заполнится позже
	serialNumber := issuerSerial.CreateElement("ds:X509SerialNumber")
	serialNumber.SetText("") // заполнится позже

	return signature
}

// addXAdESCertificateInfo добавляет информацию о сертификате в XAdES
func addXAdESCertificateInfo(signature *etree.Element, cert *x509.Certificate) error {
	// Вычисляем дайджест сертификата
	certDigestAlgorithm := "http://www.w3.org/2001/04/xmldsig-more#gostr3411"
	if !IsAlgorithmSupported(certDigestAlgorithm) {
		certDigestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256"
	}

	certDigest, err := ComputeDigest(cert.Raw, certDigestAlgorithm)
	if err != nil {
		return fmt.Errorf("ошибка вычисления дайджеста сертификата: %w", err)
	}

	// Находим элементы и заполняем их
	digestValueElem := signature.FindElement(".//xades:CertDigest/ds:DigestValue")
	if digestValueElem != nil {
		digestValueElem.SetText(base64.StdEncoding.EncodeToString(certDigest))
	}

	issuerNameElem := signature.FindElement(".//xades:IssuerSerial/ds:X509IssuerName")
	if issuerNameElem != nil {
		issuerNameElem.SetText(cert.Issuer.String())
	}

	serialNumberElem := signature.FindElement(".//xades:IssuerSerial/ds:X509SerialNumber")
	if serialNumberElem != nil {
		serialNumberElem.SetText(cert.SerialNumber.String())
	}

	return nil
}

// findElement ищет элемент по имени
func findElement(root *etree.Element, name string) *etree.Element {
	return root.FindElement(".//" + name)
}
