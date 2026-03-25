package giskh_xmlsig

import "encoding/xml"

// Signature представляет XML цифровую подпись для ГИС ЖКХ
type Signature struct {
	XMLName        xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	ID             string   `xml:"Id,attr"`
	SignedInfo     SignedInfo
	SignatureValue string
	KeyInfo        KeyInfo
	Object         Object `xml:"Object"`
}

// SignedInfo содержит информацию о подписываемых данных
type SignedInfo struct {
	CanonicalizationMethod CanonicalizationMethod
	SignatureMethod        SignatureMethod
	Reference              Reference
}

// Reference содержит ссылку на подписываемые данные
type Reference struct {
	URI          string `xml:"URI,attr"`
	Transforms   Transforms
	DigestMethod DigestMethod
	DigestValue  string
}

// DigestMethod определяет алгоритм хэширования
type DigestMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// Transforms содержит преобразования данных
type Transforms struct {
	Transform []Transform
}

// Transform определяет преобразование
type Transform struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// SignatureMethod определяет алгоритм подписи
type SignatureMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// CanonicalizationMethod определяет алгоритм каноникализации
type CanonicalizationMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// KeyInfo содержит информацию о ключе
type KeyInfo struct {
	X509Data X509Data
}

// X509Data содержит данные сертификата
type X509Data struct {
	X509Certificate string
}

// Object содержит дополнительные свойства подписи
type Object struct {
	QualifyingProperties QualifyingProperties
}

// QualifyingProperties содержит свойства XAdES
type QualifyingProperties struct {
	Target           string `xml:"Target,attr"`
	XMLNS            string `xml:"xmlns:xades,attr"`
	SignedProperties SignedProperties
}

// SignedProperties содержит подписанные свойства
type SignedProperties struct {
	ID                        string `xml:"Id,attr"`
	SignedSignatureProperties SignedSignatureProperties
}

// SignedSignatureProperties содержит свойства подписи
type SignedSignatureProperties struct {
	SigningCertificate SigningCertificate
}

// SigningCertificate содержит информацию о сертификате
type SigningCertificate struct {
	Cert Cert
}

// Cert содержит данные сертификата
type Cert struct {
	CertDigest   CertDigest
	IssuerSerial IssuerSerial
}

// CertDigest содержит дайджест сертификата
type CertDigest struct {
	DigestMethod DigestMethod
	DigestValue  string
}

// IssuerSerial содержит информацию об издателе
type IssuerSerial struct {
	X509IssuerName   string
	X509SerialNumber string
}

// SOAPEnvelope представляет SOAP конверт
type SOAPEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Header  SOAPHeader
	Body    SOAPBody
}

// SOAPHeader содержит заголовок SOAP
type SOAPHeader struct {
	Security Security `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Security"`
}

// Security содержит элемент безопасности
type Security struct {
	XMLName             xml.Name `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Security"`
	Signature           *Signature
	BinarySecurityToken string `xml:"BinarySecurityToken"`
}

// SOAPBody содержит тело SOAP
type SOAPBody struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	ID      string   `xml:"Id,attr"`
	Content string   `xml:",innerxml"`
}
