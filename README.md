# ГИС ЖКХ XML Digital Signature

Библиотека для создания XML цифровых подписей соответствующих требованиям ГИС ЖКХ (Государственная информационная система жилищно-коммунального хозяйства).

## Особенности

- **Поддержка ГИС ЖКХ**: Реализует профиль XMLDSig для интеграции с ГИС ЖКХ
- **XAdES-BES**: Поддержка расширенных электронных подписей
- **SOAP конверты**: Работа с SOAP документами с правильными namespace
- **EXC-C14N**: Правильная эксклюзивная каноникализация XML
- **Алгоритмы ГОСТ**: Заготовка для алгоритмов ГОСТ Р 34.10-2001/34.11-94
- **RSA поддержка**: Полная поддержка RSA для тестирования

## Структура

```
├── signer.go          # Основная функция подписания
├── types.go           # Структуры данных XMLDSig и SOAP
├── canonicalize.go    # Каноникализация XML (EXC-C14N)
├── gost.go            # Поддержка алгоритмов ГОСТ (заглушки)
├── example/
│   └── main.go        # Пример использования
└── README.md
```

## Установка

```bash
go get github.com/Pavel-Vinogradov/giskh-xmlsig
```

## Использование

### Базовое использование

```go
package main

import (
    "crypto/x509"
    "github.com/Pavel-Vinogradov/giskh-xmlsig"
)

func main() {
    // Загрузка сертификата и приватного ключа
    cert, privateKey := loadCertificate()
    
    // SOAP документ для подписания
    soapXML := `<?xml version="1.0" encoding="UTF-8"?>
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
        <soapenv:Header/>
        <soapenv:Body>
            <!-- Данные ГИС ЖКХ -->
        </soapenv:Body>
    </soapenv:Envelope>`
    
    // Подписание документа
    signedXML, err := giskh_xmlsig.SignXMLGIS([]byte(soapXML), cert, privateKey)
    if err != nil {
        panic(err)
    }
    
    println(string(signedXML))
}
```

### Пример запуска

```bash
cd example
go run main.go
```

## Структура подписи

Библиотека создает подписи соответствующие профилю ГИС ЖКХ:

```xml
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="xmldsig">
    <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411"/>
        <ds:Reference URI="#Body">
            <ds:Transforms>
                <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#gostr3411"/>
            <ds:DigestValue>...</ds:DigestValue>
        </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>...</ds:SignatureValue>
    <ds:KeyInfo>
        <ds:X509Data>
            <ds:X509Certificate>...</ds:X509Certificate>
        </ds:X509Data>
    </ds:KeyInfo>
    <ds:Object>
        <xades:QualifyingProperties Target="#xmldsig" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
            <!-- XAdES-BES свойства -->
        </xades:QualifyingProperties>
    </ds:Object>
</ds:Signature>
```

## Алгоритмы

### Поддерживаемые алгоритмы

- **RSA-SHA256**: Полная поддержка
- **ГОСТ Р 34.10-2001/34.11-94**: Заглушки (требует библиотеку ГОСТ)

### Каноникализация

- **EXC-C14N**: Эксклюзивная каноникализация
- **Enveloped Signature**: Удаление вложенных подписей

## Требования ГИС ЖКХ

Библиотека соответствует требованиям:

1. **Профиль OASIS Standard 200401** с X.509 Certificate Token Profile
2. **XAdES-BES** (XML Advanced Electronic Signature - Basic Electronic Signature)
3. **SOAP конверты** с правильными namespace
4. **Трансформации данных** перед подписанием
5. **Алгоритмы ГОСТ** (заглушки для реализации)

## Зависимости

```go
require (
    github.com/beevik/etree v1.6.0
)
```

## Лицензия

MIT License
