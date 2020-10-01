package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/micro-gis/oauth-go/oauth/errors"
	"github.com/federicoleon/go-httpclient/gohttp"
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
	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == ""{
		return nil
	}
	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status == http.StatusNotFound{
			return nil
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

func getAccessToken(accessTokenId string)(*accessToken, *errors.RestErr){
	response, err := oauthRestClient.Get(fmt.Sprintf("http://127.0.0.1:8087/oauth/access_token/%s",accessTokenId))
	if err != nil {
		return nil, errors.NewBadRequestError("invalid access token provided")
	}
	if response == nil || response.StatusCode < 100 {
		return nil, errors.NewInternalServerError("invalid restClient response when trying to get access token")
	}

	if response.StatusCode > 299 {
		var restErr errors.RestErr
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			return nil, errors.NewInternalServerError("invalid error interface when trying to login user")
		}
		return nil, &restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, errors.NewInternalServerError("error when trying to unmarshall access token")
	}
	return &at, nil
}