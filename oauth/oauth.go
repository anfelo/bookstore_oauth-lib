package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/anfelo/bookstore_oauth-lib/utils/errors"
	"github.com/go-resty/resty/v2"
)

const (
	headerXPublic       = "X-Public"
	headerXClientID     = "X-Client-Id"
	headerXCallerID     = "X-Caller-Id"
	headerAuthorization = "Authorization"
)

var (
	restClient = resty.New()
)

type accessToken struct {
	ID       string `json:"id"`
	UserID   string `json:"user_id"`
	ClientID string `json:"client_id"`
}

// IsPublic method checks if request is public
func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

// AuthenticateRequest method authenticates a request
func AuthenticateRequest(request *http.Request) *errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessToken := strings.TrimSpace(request.Header.Get(headerAuthorization))
	if accessToken == "" {
		return nil
	}

	at, err := getAccessToken(accessToken)
	if err != nil {
		return err
	}

	request.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientID))
	request.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserID))

	return nil
}

// GetClientID method gets the client id from request headers
func GetClientID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientID, err := strconv.ParseInt(request.Header.Get(headerXClientID), 10, 64)
	if err != nil {
		return 0
	}
	return clientID
}

// GetCallerID method gets the caller id from request headers
func GetCallerID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerID, err := strconv.ParseInt(request.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientID)
	request.Header.Del(headerXCallerID)
}

func getAccessToken(accessTokenID string) (*accessToken, *errors.RestErr) {
	resp, err := restClient.R().Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenID))
	if err != nil {
		return nil, errors.NewInternatServerError("invalid restclient request")
	}

	if resp == nil || resp.RawResponse == nil {
		return nil, errors.NewInternatServerError("invalid restclient response when trying to get access token")
	}
	if resp.StatusCode() > 299 {
		var restErr errors.RestErr
		err := json.Unmarshal(resp.Body(), &restErr)
		if err != nil {
			return nil, errors.NewInternatServerError("invalid error interface when trying to get access token")
		}
		return nil, &restErr
	}

	var at accessToken
	if err := json.Unmarshal(resp.Body(), &at); err != nil {
		return nil, errors.NewInternatServerError("error when trying to unmarshal access token response")
	}
	return &at, nil
}
