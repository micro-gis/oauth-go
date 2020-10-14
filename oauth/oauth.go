package oauth

import (
	"encoding/json"
	"fmt"
	errors2 "github.com/micro-gis/utils/rest_errors"
	"github.com/yossefaz/go-http-client/gohttp"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerPublic = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"
	paramAccessToken="access_token"
	baseOauthURL="http://127.0.0.1:8087"
)

var  (
	oauthRestClient gohttp.Client
)

type accessToken struct {
	Id string `json:"id"`
	UserId int64 `json:"user_id"`
	ClientId int64 `json:"client_id"`
}

func init() {
	oauthRestClient = gohttp.NewBuilder().SetConnectionTimeout(200 * time.Millisecond).Build()
}

func getTokenParamFromRequest(request *http.Request) (*string, errors2.RestErr) {
	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == ""{
		return nil, errors2.NewUnauthorizedError("access token is missing")
	}
	return &accessTokenId, nil
}

func IsPublic(request *http.Request) bool {
	err := AuthenticateRequest(request)
	if err != nil {
		return true
	}
	if request == nil {
		return true
	}
	if request.Header.Get(headerXCallerId) != "" {
		return false
	}
	if request.Header.Get(headerPublic) == "true" {
		return true
	}
	if request.Header.Get(headerPublic) == "" && request.Header.Get(headerXCallerId) == "" {
		return true
	}

	return true
}

func AuthenticateRequest(request *http.Request) errors2.RestErr{
	if request == nil {
		return nil
	}
	cleanRequest(request)

	accessTokenId, err := getTokenParamFromRequest(request)
	if err != nil {
		return nil
	}
	at, err := getAccessToken(*accessTokenId)
	if err != nil {
		if err.Status() == http.StatusNotFound{
			return errors2.NewUnauthorizedError("unknown token provided")
		}
		return err
	}
	request.Header.Add(headerXClientId, fmt.Sprintf("%v",at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v",at.UserId))

	return nil
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64{
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}


func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}



func getAccessToken(accessTokenId string)(*accessToken, errors2.RestErr){
	response, err := oauthRestClient.Get(fmt.Sprintf("%s/oauth/access_token/%s",baseOauthURL, accessTokenId))
	if err != nil {
		return nil, errors2.NewBadRequestError("invalid access token provided")
	}
	if response == nil || response.StatusCode < 100 {
		return nil, errors2.NewInternalServerError("invalid restClient response when trying to get access token", err)
	}

	if response.StatusCode > 299 {
		restErr, err := errors2.NewRestErrorFromBytes(response.Bytes())
		if err != nil {
			return nil, errors2.NewInternalServerError("invalid error interface when trying to login user", err)
		}
		return nil, restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, errors2.NewInternalServerError("error when trying to unmarshall access token", err)
	}
	return &at, nil
}

func DeleteAllAccessToken(request *http.Request)errors2.RestErr{
	accessTokenId, err := getTokenParamFromRequest(request)
	if err != nil {
		return err
	}
	response, delerr := oauthRestClient.Delete(fmt.Sprintf("%s/oauth/access_token/%s",baseOauthURL, *accessTokenId))
	if response == nil || response.StatusCode < 100 {
		return errors2.NewInternalServerError("invalid restClient response when trying to delete user's token", delerr)
	}

	if response.StatusCode > 299 {
		restErr, err := errors2.NewRestErrorFromBytes(response.Bytes())
		if err != nil {
			return errors2.NewInternalServerError("invalid error interface when trying to delete user's token", err)
		}
		return restErr
	}
	return nil
}