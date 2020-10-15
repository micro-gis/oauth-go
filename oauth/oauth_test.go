package oauth

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/yossefaz/go-http-client/gohttp_mock"
	"net/http"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	gohttp_mock.MockupServer.Start()
	os.Exit(m.Run())

}

func TestOauthConstants(t *testing.T) {
	assert.EqualValues(t, "X-Public", headerPublic)
	assert.EqualValues(t, "X-Client-Id", headerXClientId)
	assert.EqualValues(t, "X-Caller-Id", headerXCallerId)
	assert.EqualValues(t, "access_token", paramAccessToken)
	assert.EqualValues(t, "http://127.0.0.1:8087", baseOauthURL)
}

func TestIsPublicNilRequest(t *testing.T) {
	assert.True(t, IsPublic(nil))
}

func TestIsPublicNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add(headerXCallerId, "1")
	assert.False(t, IsPublic(&request))
	request.Header.Del(headerXCallerId)
	request.Header.Add(headerPublic, "true")
	assert.True(t, IsPublic(&request))

	request.Header.Del(headerPublic)
	assert.True(t, IsPublic(&request))
}

func TestGetAccessTokenInvalidRestClientResponse(t *testing.T) {
	accessTokenId := "sdskd"
	gohttp_mock.MockupServer.DeleteMocks()
	gohttp_mock.MockupServer.AddMock(gohttp_mock.Mock{
		Method:      http.MethodGet,
		Url:         fmt.Sprintf("%s/oauth/access_token/%s",baseOauthURL, accessTokenId),
		ResponseStatusCode: 0,
		ResponseBody: "",
	})

	accessToken, err := getAccessToken(accessTokenId)
	assert.Nil(t, accessToken)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusInternalServerError, err.Status())
	assert.EqualValues(t, "invalid restClient response when trying to get access token", err.Message())



}
