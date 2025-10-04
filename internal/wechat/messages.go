package wechat

import (
    "encoding/json"
    "encoding/xml"
    "errors"
)

// EncryptedEnvelopeFormat indicates the serialization used by the webhook payload.
type EncryptedEnvelopeFormat int

const (
    UnknownEnvelope EncryptedEnvelopeFormat = iota
    XMLEnvelope
    JSONEnvelope
)

// ExtractEncryptedField inspects the request body and returns the encrypted field and its format.
func ExtractEncryptedField(body []byte) (string, EncryptedEnvelopeFormat, error) {
    var xmlEnvelope struct {
        Encrypt string `xml:"Encrypt"`
    }
    if err := xml.Unmarshal(body, &xmlEnvelope); err == nil && xmlEnvelope.Encrypt != "" {
        return xmlEnvelope.Encrypt, XMLEnvelope, nil
    }

    var jsonEnvelope struct {
        Encrypt string `json:"encrypt"`
    }
    if err := json.Unmarshal(body, &jsonEnvelope); err == nil && jsonEnvelope.Encrypt != "" {
        return jsonEnvelope.Encrypt, JSONEnvelope, nil
    }

    return "", UnknownEnvelope, errors.New("no encrypt field found in body")
}

// TokenEnvelope contains the token and open kf id extracted from the decrypted body.
type TokenEnvelope struct {
    Token    string
    OpenKfID string
}

// ExtractTokenEnvelope attempts to parse token metadata from decrypted XML or JSON payloads.
func ExtractTokenEnvelope(data []byte) (TokenEnvelope, error) {
    var xmlPayload struct {
        Token    string `xml:"Token" json:"Token"`
        OpenKfID string `xml:"OpenKfId" json:"OpenKfId"`
    }
    if err := xml.Unmarshal(data, &xmlPayload); err == nil && xmlPayload.Token != "" {
        return TokenEnvelope{Token: xmlPayload.Token, OpenKfID: xmlPayload.OpenKfID}, nil
    }

    var jsonPayload struct {
        Token    string `json:"token"`
        OpenKfID string `json:"open_kfid"`
    }
    if err := json.Unmarshal(data, &jsonPayload); err == nil && jsonPayload.Token != "" {
        return TokenEnvelope{Token: jsonPayload.Token, OpenKfID: jsonPayload.OpenKfID}, nil
    }

    return TokenEnvelope{}, errors.New("token metadata not found in payload")
}

