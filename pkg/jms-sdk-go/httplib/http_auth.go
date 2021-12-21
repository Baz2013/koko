package httplib

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)


var (
	_ AuthSign = (*SigAuth)(nil)

	_ AuthSign = (*BasicAuth)(nil)

	_ AuthSign = (*BearerTokenAuth)(nil)
)

const (
	signHeaderRequestTarget = "(request-target)"
	signHeaderDate          = "date"
	signAlgorithm           = "hmac-sha256"
)

type SigAuth struct {
	KeyID    string
	SecretID string
}

func (auth *SigAuth) Sign(r *http.Request) error {
	//headers := []string{signHeaderRequestTarget, signHeaderDate}
	//signer, err := httpsig.NewRequestSigner(auth.KeyID, auth.SecretID, signAlgorithm)
	//if err != nil {
	//	return err
	//}

	date := time.Now().UTC().Format(http.TimeFormat)
	//fmt.Println("------------Date: " + date)
	r.Header.Set("Date", date)
	signature := makeSignature(auth.SecretID, date)
	r.Header.Set("AUTHORIZATION", fmt.Sprintf("Sign %s:%s", auth.KeyID, signature))
	//fmt.Println("------------Authorization: " + fmt.Sprintf("Sign %s:%s", key.ID, signature))

	return nil
}

type BasicAuth struct {
	Username string
	Password string
}

func (auth *BasicAuth) Sign(r *http.Request) error {
	r.SetBasicAuth(auth.Username, auth.Password)
	return nil
}

type BearerTokenAuth struct {
	Token string
}

func (auth *BearerTokenAuth) Sign(r *http.Request) error {
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
	return nil
}

/**
与 uss 中验证方法计算出的签名一致
*/
func makeSignature(secret string, date string) string {
	data := secret + "\n" + date
	h := md5.New()
	h.Write([]byte(data))
	//d5 := h.Sum(nil)
	//sEnc := base64.StdEncoding.EncodeToString(d5)

	return base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(h.Sum(nil))))
}
