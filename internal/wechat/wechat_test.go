package wechat

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func TestVerifySignature(t *testing.T) {
	token := "token"
	timestamp := "123456"
	nonce := "nonce"
	signature := "c2346eeb6da94f9b91fb38a7d0e1f55139d9d45d"

	if !VerifySignature(token, signature, timestamp, nonce) {
		t.Fatalf("expected signature to verify")
	}
	if VerifySignature(token, "bogus", timestamp, nonce) {
		t.Fatalf("expected verification to fail for bogus signature")
	}
}

func TestVerifyMessageSignature(t *testing.T) {
	token := "token"
	timestamp := "123456"
	nonce := "nonce"
	encrypted := "cipher"
	signature := "8e709dba616d5a0f210c16fb0ff992d47e517e48"

	if !VerifyMessageSignature(token, signature, timestamp, nonce, encrypted) {
		t.Fatalf("expected msg signature to verify")
	}

	if VerifyMessageSignature(token, "deadbeef", timestamp, nonce, encrypted) {
		t.Fatalf("expected mismatch to fail")
	}
}

func TestCrypterDecrypt(t *testing.T) {
	encodingKey := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"
	corpID := "corp123"
	message := []byte("<xml><Token>abc</Token></xml>")

	encrypted := mustEncrypt(t, encodingKey, corpID, message)
	crypter, err := NewCrypter(encodingKey, corpID)
	if err != nil {
		t.Fatalf("crypter init failed: %v", err)
	}

	decrypted, err := crypter.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, message) {
		t.Fatalf("unexpected plaintext: %s", decrypted)
	}

	wrongCrypter, err := NewCrypter(encodingKey, "other")
	if err != nil {
		t.Fatalf("wrong crypter init failed: %v", err)
	}
	if _, err := wrongCrypter.Decrypt(encrypted); err == nil {
		t.Fatalf("expected corpID mismatch error")
	}
}

func TestExtractEncryptedField(t *testing.T) {
	xmlBody := []byte(`<xml><Encrypt>ENC</Encrypt></xml>`)
	jsonBody := []byte(`{"encrypt":"ENC"}`)

	enc, format, err := ExtractEncryptedField(xmlBody)
	if err != nil || enc != "ENC" || format != XMLEnvelope {
		t.Fatalf("expected xml extraction, got %q %v %v", enc, format, err)
	}

	enc, format, err = ExtractEncryptedField(jsonBody)
	if err != nil || enc != "ENC" || format != JSONEnvelope {
		t.Fatalf("expected json extraction, got %q %v %v", enc, format, err)
	}

	if _, _, err := ExtractEncryptedField([]byte("noop")); err == nil {
		t.Fatalf("expected error for missing encrypt field")
	}
}

func TestExtractTokenEnvelope(t *testing.T) {
	xmlPayload := []byte(`<xml><Token>abc</Token><OpenKfId>kf</OpenKfId></xml>`)
	env, err := ExtractTokenEnvelope(xmlPayload)
	if err != nil || env.Token != "abc" || env.OpenKfID != "kf" {
		t.Fatalf("unexpected xml env: %+v err=%v", env, err)
	}

	jsonPayload := []byte(`{"token":"abc","open_kfid":"kf"}`)
	env, err = ExtractTokenEnvelope(jsonPayload)
	if err != nil || env.Token != "abc" || env.OpenKfID != "kf" {
		t.Fatalf("unexpected json env: %+v err=%v", env, err)
	}

	if _, err := ExtractTokenEnvelope([]byte(`{"token": ""}`)); err == nil {
		t.Fatalf("expected error for missing token")
	}
}

func mustEncrypt(t *testing.T, encodingKey, corpID string, message []byte) string {
	t.Helper()

	key, err := base64.StdEncoding.DecodeString(encodingKey + "=")
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher init: %v", err)
	}

	random := bytes.Repeat([]byte("A"), 16)
	buf := make([]byte, 0, len(random)+4+len(message)+len(corpID))
	buf = append(buf, random...)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(message)))
	buf = append(buf, length...)
	buf = append(buf, message...)
	buf = append(buf, []byte(corpID)...)

	pad := 32 - len(buf)%32
	buf = append(buf, bytes.Repeat([]byte{byte(pad)}, pad)...)

	cipherText := make([]byte, len(buf))
	cipher.NewCBCEncrypter(block, key[:aes.BlockSize]).CryptBlocks(cipherText, buf)
	return base64.StdEncoding.EncodeToString(cipherText)
}
