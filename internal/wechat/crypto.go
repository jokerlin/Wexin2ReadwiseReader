package wechat

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "encoding/binary"
    "errors"
    "fmt"
)

// Crypter handles AES-CBC decryption as required by WeChat encrypted callbacks.
type Crypter struct {
    key    []byte
    corpID string
}

// NewCrypter initialises a Crypter from the 43 character EncodingAESKey and corp/app ID.
func NewCrypter(encodingAESKey, corpID string) (*Crypter, error) {
    if encodingAESKey == "" {
        return nil, errors.New("missing EncodingAESKey")
    }
    if len(encodingAESKey) != 43 {
        return nil, fmt.Errorf("EncodingAESKey must be 43 characters; got %d", len(encodingAESKey))
    }

    key, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
    if err != nil {
        return nil, fmt.Errorf("invalid EncodingAESKey: %w", err)
    }
    if len(key) != 32 {
        return nil, fmt.Errorf("decoded key length must be 32 bytes; got %d", len(key))
    }

    return &Crypter{key: key, corpID: corpID}, nil
}

// Decrypt base64 encoded ciphertext and return the underlying XML/JSON payload.
func (c *Crypter) Decrypt(encrypted string) ([]byte, error) {
    if encrypted == "" {
        return nil, errors.New("empty encrypted payload")
    }

    cipherText, err := base64.StdEncoding.DecodeString(encrypted)
    if err != nil {
        return nil, fmt.Errorf("cipher decode failed: %w", err)
    }
    if len(cipherText) < aes.BlockSize || len(cipherText)%aes.BlockSize != 0 {
        return nil, errors.New("invalid ciphertext length")
    }

    block, err := aes.NewCipher(c.key)
    if err != nil {
        return nil, fmt.Errorf("cipher init failed: %w", err)
    }

    iv := c.key[:aes.BlockSize]
    mode := cipher.NewCBCDecrypter(block, iv)
    plain := make([]byte, len(cipherText))
    mode.CryptBlocks(plain, cipherText)

    plain, err = pkcs7Unpad(plain)
    if err != nil {
        return nil, err
    }
    if len(plain) < 20 {
        return nil, errors.New("plaintext shorter than minimum frame")
    }

    msgLen := binary.BigEndian.Uint32(plain[16:20])
    end := 20 + int(msgLen)
    if end > len(plain) {
        return nil, errors.New("reported message length exceeds plaintext bounds")
    }

    message := plain[20:end]
    tail := plain[end:]
    if c.corpID != "" && string(tail) != c.corpID {
        return nil, fmt.Errorf("corp/app id mismatch: expect %s got %s", c.corpID, tail)
    }
    return message, nil
}

func pkcs7Unpad(data []byte) ([]byte, error) {
    if len(data) == 0 {
        return nil, errors.New("pkcs7: empty data")
    }
    pad := int(data[len(data)-1])
    if pad <= 0 || pad > 32 {
        return nil, errors.New("pkcs7: invalid padding size")
    }
    if pad > len(data) {
        return nil, errors.New("pkcs7: padding larger than block")
    }
    for i := len(data) - pad; i < len(data); i++ {
        if int(data[i]) != pad {
            return nil, errors.New("pkcs7: non-uniform padding byte")
        }
    }
    return data[:len(data)-pad], nil
}

// DecryptEchoString decrypts an encrypted echostr and returns the plain text response expected by WeChat.
func (c *Crypter) DecryptEchoString(echostr string) (string, error) {
    msg, err := c.Decrypt(echostr)
    if err != nil {
        return "", err
    }
    return string(msg), nil
}
