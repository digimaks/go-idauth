// SPDX-License-Identifier: EUPL-1.2

package authorization

import (
	"encoding/base64"

	"github.com/nobid-lsp-latvia/go-idauth"

	"azugo.io/azugo"
	"azugo.io/core/http"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

type router struct {
	config       *idauth.Configuration
	idauthClient *idauth.Client
}

func Bind(g azugo.Router, config *idauth.Configuration) error {
	client, err := idauth.NewClient(config)
	if err != nil {
		return err
	}

	r := &router{
		config:       config,
		idauthClient: client,
	}

	v1 := g.Group("/1.0")

	v1.Post("/token", r.token)
	v1.Get("/session", r.session)

	return nil
}

func (r *router) token(ctx *azugo.Context) {
	client := ctx.HTTPClient()

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	ctx.Request().CopyTo(req)
	req.SetRequestURI(r.config.URL + "/api/1.0/token")
	req.Header.SetMethod("POST")

	// Add the Authorization header
	req.Header.Set("Authorization", BasicAuthHeader(r.config.ClientID, r.config.ClientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp := &ctx.Context().Response

	httpRequest := &http.Request{
		Request: req,
	}

	httpResponse := &http.Response{
		Response: resp,
	}

	err := client.Do(httpRequest, httpResponse)
	if err != nil {
		ctx.Log().Error("failed to get token", zap.Error(err))
		ctx.Error(err)

		return
	}

	ctx.Raw(httpResponse.Body())
	ctx.StatusCode(httpResponse.StatusCode())
}

func (r *router) session(ctx *azugo.Context) {
	userinfo, err := r.idauthClient.UserInfo(ctx, ctx.Header.InheritAuthorization())
	if err != nil {
		ctx.Error(err)

		return
	}

	if !userinfo.Active {
		ctx.Error(http.UnauthorizedError{})

		return
	}

	ctx.JSON(userinfo)
}

// BasicAuthHeader generates a Basic Authorization header string.
func BasicAuthHeader(username, password string) string {
	auth := username + ":" + password

	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}
