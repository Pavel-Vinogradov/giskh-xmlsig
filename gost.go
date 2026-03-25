package giskh_xmlsig

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"strings"
)

// GOSTPrivateKey представляет приватный ключ ГОСТ (заглушка)
type GOSTPrivateKey struct {
	// TODO: Реализовать с использованием библиотеки ГОСТ
}

// GOSTPublicKey представляет публичный ключ ГОСТ (заглушка)
type GOSTPublicKey struct {
	// TODO: Реализовать с использованием библиотеки ГОСТ
}

// SignDataGOST подписывает данные с использованием алгоритма ГОСТ Р 34.10-2001
func SignDataGOST(data []byte, privateKey crypto.PrivateKey) ([]byte, error) {
	switch key := privateKey.(type) {
	case *GOSTPrivateKey:
		// TODO: Реализовать подпись ГОСТ
		return nil, fmt.Errorf("подпись ГОСТ не реализована - требуется библиотека")
	case *rsa.PrivateKey:
		// Для совместимости оставляем RSA
		return SignDataRSA(data, key)
	default:
		return nil, fmt.Errorf("неподдерживаемый тип ключа для ГОСТ")
	}
}

// SignDataRSA подписывает данные с использованием RSA-PKCS1v15
func SignDataRSA(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hash := computeSHA256(data)
	return rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, hash)
}

// ComputeDigestGOST вычисляет дайджест ГОСТ Р 34.11-94
func ComputeDigestGOST(data []byte) ([]byte, error) {
	// TODO: Реализовать дайджест ГОСТ Р 34.11-94
	// Временно используем SHA256 как заглушку
	return computeSHA256(data), nil
}

// VerifyGOST проверяет подпись ГОСТ
func VerifyGOST(data, signature []byte, publicKey crypto.PublicKey) error {
	switch key := publicKey.(type) {
	case *GOSTPublicKey:
		// TODO: Реализовать проверку ГОСТ
		return fmt.Errorf("проверка ГОСТ не реализована - требуется библиотека")
	case *rsa.PublicKey:
		return VerifyRSA(data, signature, key)
	default:
		return fmt.Errorf("неподдерживаемый тип публичного ключа")
	}
}

// VerifyRSA проверяет RSA подпись
func VerifyRSA(data, signature []byte, publicKey *rsa.PublicKey) error {
	hash := computeSHA256(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash, signature)
}

// GetSupportedAlgorithms возвращает список поддерживаемых алгоритмов
func GetSupportedAlgorithms() map[string]string {
	return map[string]string{
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":              "RSA-SHA256",
		"http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411": "ГОСТ Р 34.10-2001/34.11-94 (требует библиотеку)",
		"http://www.w3.org/2001/04/xmlenc#sha256":                        "SHA256",
		"http://www.w3.org/2001/04/xmldsig-more#gostr3411":               "ГОСТ Р 34.11-94 (требует библиотеку)",
	}
}

// IsAlgorithmSupported проверяет поддержку алгоритма
func IsAlgorithmSupported(algorithm string) bool {
	algorithms := GetSupportedAlgorithms()
	_, supported := algorithms[algorithm]
	// ГОСТ алгоритмы пока не поддерживаем
	return supported && !contains(algorithm, "gost")
}

// contains проверяет содержится ли подстрока в строке (case-insensitive)
func contains(s, substr string) bool {
	s = strings.ToLower(s)
	substr = strings.ToLower(substr)
	return strings.Contains(s, substr)
}
