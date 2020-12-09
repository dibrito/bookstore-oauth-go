package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mercadolibre/golang-restclient/rest"

	"github.com/dibrito/book-store-oauth-go/errors"
	"github.com/dibrito/bookstore-users-api/logger"
)

const (
	headerXPublic   = "X-Public"
	headerXClientID = "X-Client-Id"
	headerXCallerID = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		Timeout: 200 * time.Millisecond,
		BaseURL: "http://localhost:8080",
	}
)

type oauthClient struct {
}

type oauthInterface interface {
}

type accessToken struct {
	Id       string `json:"id"`
	UserId   string `json:"user_id"`
	ClientId string `json:"client_id"`
}

func GetCallerId(req *http.Request) int64 {
	if req == nil {
		return 0
	}
	callerID, err := strconv.ParseInt(req.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

func GetClientId(req *http.Request) int64 {
	if req == nil {
		return 0
	}
	clientID, err := strconv.ParseInt(req.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}

	return clientID
}

func IsPublic(req *http.Request) bool {
	if req == nil {
		return true
	}
	return req.Header.Get(headerXPublic) == "true"
}

func AuthenticateRequest(req *http.Request) *errors.RestErr {
	logger.Info("AuthenticateRequest")
	if req == nil {
		return nil
	}
	cleanRequest(req)
	accessTokenID := strings.TrimSpace(req.URL.Query().Get(paramAccessToken))
	// "https://api.bookstore.com/resource?access_token=abc123"
	if accessTokenID == "" {
		return nil
	}
	logger.Info(fmt.Sprintf("accessTokenID:%v", accessTokenID))
	at, err := getAccessToken(accessTokenID)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}
	req.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserId))
	req.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientId))
	return nil
}

func cleanRequest(req *http.Request) {
	if req == nil {
		return
	}
	req.Header.Del(headerXClientID)
	req.Header.Del(headerXCallerID)
}

func getAccessToken(accessTokenID string) (*accessToken, *errors.RestErr) {
	resp := oauthRestClient.Get(fmt.Sprintf("oauth/access_token/%s", accessTokenID))
	if resp == nil {
		return nil, errors.NewInternalServerError("invalid_rest_client_response_when_trying_to_get_access_token")
	}
	if resp.StatusCode > 299 {
		var restError errors.RestErr
		err := json.Unmarshal(resp.Bytes(), &restError)
		if err != nil {
			return nil, errors.NewInternalServerError("invalid_error_interface_when_trying_to_login_user")
		}
		return nil, &restError
	}
	var at accessToken
	if err := json.Unmarshal(resp.Bytes(), &at); err != nil {
		return nil, errors.NewInternalServerError("error_trying_to_unmarshall_access_token_response")
	}
	return &at, nil

}
