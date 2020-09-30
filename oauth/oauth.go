package oauth

import (
	"github.com/micro-gis/oauth-go/oauth/errors"
	"net/http"
	"strings"
)

const (
	headerPublic = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"
	paramAccessToken="access_token"
)

type oauthClient struct {

}

type oauthInterface interface {

}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerPublic) == "true"
}

func AuthenticateRequest(request *http.Request) *errors.RestErr{
	if request == nil {
		return nil
	}
	accessToken := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessToken == ""{
		return nil
	}
	return nil
}