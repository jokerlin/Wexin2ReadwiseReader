package wechat

import (
    "crypto/sha1"
    "encoding/hex"
    "io"
    "sort"
)

// VerifySignature validates the standard WeChat signature produced from token, timestamp, and nonce.
func VerifySignature(token, signature, timestamp, nonce string) bool {
    if token == "" {
        return false
    }
    items := []string{token, timestamp, nonce}
    sort.Strings(items)
    h := sha1.New()
    _, _ = io.WriteString(h, items[0]+items[1]+items[2])
    calc := hex.EncodeToString(h.Sum(nil))
    return calc == signature
}

// VerifyMessageSignature validates the encrypted message signature which includes the encrypted payload.
func VerifyMessageSignature(token, msgSignature, timestamp, nonce, encrypted string) bool {
    if token == "" {
        return false
    }
    items := []string{token, timestamp, nonce, encrypted}
    sort.Strings(items)
    h := sha1.New()
    _, _ = io.WriteString(h, items[0]+items[1]+items[2]+items[3])
    calc := hex.EncodeToString(h.Sum(nil))
    return calc == msgSignature
}

