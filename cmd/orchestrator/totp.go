package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	totpPeriodSeconds = int64(30)
	totpDigits        = 6
)

var totpBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func generateTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return totpBase32.EncodeToString(raw), nil
}

func totpCode(secret string, counter int64) (string, error) {
	key, err := totpBase32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)
	code := bin % 1_000_000
	return fmt.Sprintf("%0*d", totpDigits, code), nil
}

func verifyTOTPCode(secret, code string, now time.Time, lastCounter int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	counter := now.Unix() / totpPeriodSeconds
	for _, candidate := range []int64{counter - 1, counter, counter + 1} {
		if candidate <= lastCounter {
			continue
		}
		expected, err := totpCode(secret, candidate)
		if err == nil && hmac.Equal([]byte(expected), []byte(code)) {
			return candidate, true
		}
	}
	return 0, false
}

func totpProvisioningURL(secret string) string {
	label := url.QueryEscape("TrafficWrapper:admin")
	issuer := url.QueryEscape("TrafficWrapper")
	return "otpauth://totp/" + label + "?secret=" + url.QueryEscape(secret) + "&issuer=" + issuer + "&algorithm=SHA1&digits=" + strconv.Itoa(totpDigits) + "&period=" + strconv.FormatInt(totpPeriodSeconds, 10)
}
