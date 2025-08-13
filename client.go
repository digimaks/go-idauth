// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"errors"
	"net/url"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// Client for IDAuth API.
type Client struct {
	config *Configuration

	userinfoEndpoint string
}

// NewClient creates a new IDAuth client.
func NewClient(config *Configuration) (*Client, error) {
	userinfoEndpoint, err := url.JoinPath(config.URL, "api/1.0/session")
	if err != nil {
		return nil, err
	}

	return &Client{
		config:           config,
		userinfoEndpoint: userinfoEndpoint,
	}, nil
}

// UserInfo retrieves the user information from the IDAuth userinfo endpoint.
func (c Client) UserInfo(ctx *azugo.Context, opts ...http.RequestOption) (*UserinfoResponse, error) {
	client := ctx.HTTPClient().WithBaseURL(c.userinfoEndpoint)

	userinfo := &UserinfoResponse{}

	err := client.GetJSON("", userinfo, opts...)
	if err != nil && !errors.Is(err, http.NotFoundError{}) {
		return nil, err
	}

	return userinfo, nil
}
