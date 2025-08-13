// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"slices"

	"azugo.io/azugo"
	"azugo.io/azugo/user"
	"azugo.io/core/http"
)

// Authentication middleware checks if the user is authentificated and has the required session state.
func Authentication(_ *azugo.App, config *Configuration, states ...string) azugo.RequestHandlerFunc {
	client, err := NewClient(config)
	if err != nil {
		panic(err)
	}

	if len(states) == 0 {
		states = []string{"authorized"}
	}

	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			userinfo, err := client.UserInfo(ctx, ctx.Header.InheritAuthorization())
			if err != nil {
				ctx.Error(err)

				return
			}

			if !userinfo.Active {
				ctx.Error(http.UnauthorizedError{})

				return
			}

			if !slices.Contains(states, userinfo.State) {
				ctx.Error(http.ForbiddenError{})

				return
			}

			ctx.SetUser(user.New(userinfo.ToClaims()))

			next(ctx)
		}
	}
}

// UserHasScope handler helper checks if the user has the scope.
func UserHasScope(scope string, next azugo.RequestHandler) azugo.RequestHandler {
	return func(ctx *azugo.Context) {
		if !ctx.User().HasScope(scope) {
			ctx.Error(http.ForbiddenError{})

			return
		}

		next(ctx)
	}
}

// UserHasScopeLevel hanler helper checks if the user has the scope with the specific level.
func UserHasScopeLevel(scope string, level ScopeLevel, next azugo.RequestHandler) azugo.RequestHandler {
	return func(ctx *azugo.Context) {
		if !ctx.User().HasScopeLevel(scope, string(level)) {
			ctx.Error(http.ForbiddenError{})

			return
		}

		next(ctx)
	}
}

// UserHasScopeAtLeastLevel hanler helper checks if the user has the scope with atleast specified level.
func UserHasScopeAtLeastLevel(scope string, level ScopeLevel, next azugo.RequestHandler) azugo.RequestHandler {
	return func(ctx *azugo.Context) {
		var valid bool

		for _, l := range scopeLevelPriorities {
			if ctx.User().HasScopeLevel(scope, string(l)) {
				valid = true

				break
			}

			if l == level {
				break
			}
		}

		if !valid {
			ctx.Error(http.ForbiddenError{})

			return
		}

		next(ctx)
	}
}
