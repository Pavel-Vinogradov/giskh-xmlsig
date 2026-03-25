package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/Pavel-Vinogradov/giskh-xmlsig"
)

func main() {
	// Пример использования XML подписи для ГИС ЖКХ

	// 1. Создаем тестовый сертификат и ключ
	cert, privateKey, err := generateTestCertificate()
	if err != nil {
		log.Fatal("Ошибка создания сертификата:", err)
	}

	// 2. Пример SOAP документа для ГИС ЖКХ
	soapXML := `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                  xmlns:ns="http://dom.gosuslugi.ru/schema/integration/1.0/">
    <soapenv:Header/>
    <soapenv:Body>
        <ns:exportAccountDataRequest>
            <ns:orgPPAGUID>test-org-guid</ns:orgPPAGUID>
            <ns:FIASHouseGuid>test-house-guid</ns:FIASHouseGuid>
            <ns:period>
                <ns:year>2024</ns:year>
                <ns:month>3</ns:month>
            </ns:period>
        </ns:exportAccountDataRequest>
    </soapenv:Body>
</soapenv:Envelope>`

	// 3. Подписываем XML документ
	signedXML, err := giskh_xmlsig.SignXMLGIS([]byte(soapXML), cert, privateKey)
	if err != nil {
		log.Fatal("Ошибка подписания XML:", err)
	}

	fmt.Println("Подписанный XML документ:")
	fmt.Println(string(signedXML))

	// 4. Проверяем поддерживаемые алгоритмы
	fmt.Println("\nПоддерживаемые алгоритмы:")
	algorithms := giskh_xmlsig.GetSupportedAlgorithms()
	for uri, name := range algorithms {
		supported := giskh_xmlsig.IsAlgorithmSupported(uri)
		fmt.Printf("- %s: %s (%s)\n", name, uri, map[bool]string{true: "поддерживается", false: "не поддерживается"}[supported])
	}
}

// generateTestCertificate создает тестовый сертификат и приватный ключ
func generateTestCertificate() (*x509.Certificate, *rsa.PrivateKey, error) {
	// Генерируем приватный ключ
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Создаем шаблон сертификата
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
			CommonName:   "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Создаем сертификат
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Преобразуем в *x509.Certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, privateKey, nil
}

// saveCertificateToFile сохраняет сертификат в файл
func saveCertificateToFile(cert *x509.Certificate, filename string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return saveToFile(certPEM, filename)
}

// savePrivateKeyToFile сохраняет приватный ключ в файл
func savePrivateKeyToFile(privateKey *rsa.PrivateKey, filename string) error {
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return saveToFile(keyPEM, filename)
}

// saveToFile сохраняет данные в файл
func saveToFile(data []byte, filename string) error {
	// TODO: Реализовать сохранение в файл
	fmt.Printf("Сохранение %d байт в файл %s\n", len(data), filename)
	return nil
}
