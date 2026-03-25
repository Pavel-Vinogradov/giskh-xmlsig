package giskh_xmlsig

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/beevik/etree"
)

// CanonicalizeEXC14N выполняет эксклюзивную каноникализацию XML (EXC-C14N#)
func CanonicalizeEXC14N(elem *etree.Element, inclusiveNamespaces []string) (string, error) {
	doc := etree.NewDocument()
	doc.SetRoot(elem.Copy())

	// Создаем карту префиксов для эксклюзивной каноникализации
	nsMap := make(map[string]string)
	prefixMap := make(map[string]string)

	// Собираем все неймспейсы в элементе
	collectNamespaces(elem, nsMap, prefixMap)

	// Удаляем xmlns:xml declarations
	removeXMLNSDeclarations(doc.Root())

	// Сортируем атрибуты
	sortAttributes(doc.Root())

	// Устанавливаем правильные отступы и сериализуем
	doc.Indent(0)
	xmlBytes, err := doc.WriteToBytes()
	if err != nil {
		return "", err
	}

	// Постобработка для EXC-C14N
	result := string(xmlBytes)
	result = normalizeLineEndings(result)
	result = normalizeAttributeValues(result)

	return result, nil
}

// collectNamespaces собирает все неймспейсы элемента
func collectNamespaces(elem *etree.Element, nsMap, prefixMap map[string]string) {
	for _, attr := range elem.Attr {
		if strings.HasPrefix(attr.Space, "xmlns") || attr.Space == "xmlns" {
			key := attr.Space
			if key == "" {
				key = "xmlns"
			}
			nsMap[key] = attr.Value
			if attr.Space != "" {
				prefixMap[attr.Value] = attr.Space
			}
		}
	}

	for _, child := range elem.Child {
		if childElem, ok := child.(*etree.Element); ok {
			collectNamespaces(childElem, nsMap, prefixMap)
		}
	}
}

// removeXMLNSDeclarations удаляет xmlns:xml declarations
func removeXMLNSDeclarations(elem *etree.Element) {
	attrs := make([]etree.Attr, 0, len(elem.Attr))
	for _, attr := range elem.Attr {
		if !(attr.Space == "xmlns" && attr.Key == "xml") {
			attrs = append(attrs, attr)
		}
	}
	elem.Attr = attrs

	for _, child := range elem.Child {
		if childElem, ok := child.(*etree.Element); ok {
			removeXMLNSDeclarations(childElem)
		}
	}
}

// sortAttributes сортирует атрибуты в лексикографическом порядке
func sortAttributes(elem *etree.Element) {
	sort.Slice(elem.Attr, func(i, j int) bool {
		// Сначала сравниваем неймспейс
		if elem.Attr[i].Space != elem.Attr[j].Space {
			return elem.Attr[i].Space < elem.Attr[j].Space
		}
		// Затем локальное имя
		return elem.Attr[i].Key < elem.Attr[j].Key
	})

	for _, child := range elem.Child {
		if childElem, ok := child.(*etree.Element); ok {
			sortAttributes(childElem)
		}
	}
}

// normalizeLineEndings нормализует окончания строк
func normalizeLineEndings(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

// normalizeAttributeValues нормализует значения атрибутов
func normalizeAttributeValues(s string) string {
	// Удаляем лишние пробелы в значениях атрибутов
	return strings.TrimSpace(s)
}

// CanonicalizeWithTransforms применяет трансформации перед каноникализацией
func CanonicalizeWithTransforms(elem *etree.Element, transforms []string) (string, error) {
	// Копируем элемент для трансформаций
	workingElem := elem.Copy()

	// Применяем трансформации в порядке
	for _, transform := range transforms {
		switch transform {
		case "http://www.w3.org/2000/09/xmldsig#enveloped-signature":
			// Удаляем существующие подписи
			removeEnvelopedSignatures(workingElem)
		case "http://www.w3.org/2001/10/xml-exc-c14n#":
			// EXC-C14N будет применен позже
			continue
		}
	}

	// Применяем EXC-C14N
	return CanonicalizeEXC14N(workingElem, nil)
}

// removeEnvelopedSignatures удаляет вложенные подписи
func removeEnvelopedSignatures(elem *etree.Element) {
	children := make([]etree.Token, 0, len(elem.Child))
	for _, child := range elem.Child {
		if childElem, ok := child.(*etree.Element); ok {
			// Проверяем, является ли элемент подписью
			if childElem.Tag == "Signature" &&
				(childElem.Space == "ds" || childElem.SelectAttrValue("xmlns", "") == "http://www.w3.org/2000/09/xmldsig#") {
				// Пропускаем элемент подписи
				continue
			}
			removeEnvelopedSignatures(childElem)
		}
		children = append(children, child)
	}
	elem.Child = children
}

// ComputeDigest вычисляет дайджест данных
func ComputeDigest(data []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case "http://www.w3.org/2001/04/xmlenc#sha256":
		return computeSHA256(data), nil
	case "http://www.w3.org/2001/04/xmldsig-more#gostr3411":
		// Для ГОСТ нужна соответствующая библиотека
		return nil, fmt.Errorf("ГОСТ Р 34.11-94 не реализован")
	default:
		return nil, fmt.Errorf("неподдерживаемый алгоритм дайджеста: %s", algorithm)
	}
}

// computeSHA256 вычисляет SHA256 хэш
func computeSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}
