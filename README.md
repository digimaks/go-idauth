# go-idauth

Library to authentificate requests and get user and session data.

## Built with Azugo Go Web Framework

This project is built using the [Azugo Go Web Framework](https://azugo.io), a powerful and flexible framework for building modern web applications in Go. Check out the [Azugo GitHub page](https://github.com/azugo) for more information and documentation.

## Usage

Add dependency

```sh
go get -u github.com/digimaks/go-idauth
```

Add configuration section

```go
import (
    "github.com/digimaks/go-idauth"
)

type Configuration struct {
    //...
    IDAuth *idauth.Configuration `mapstruct:"idauth"`
    IDAuthSystem *idauth.SystemTokenConfiguration `mapstructure:"system_token"`
    //...
}

func (c *Configuration) Bind(_ string, v *viper.Viper) {
    //...
    c.IDAuth = config.Bind(c.IDAuth, "idauth", v)
    c.IDAuthSystem = config.Bind(c.IDAuthSystem, "system_token", v)
    //...
}

func (c *Configuration) Validate(validate *validation.Validate) error {
    //...
    if err := c.IDAuth.Validate(validate); err != nil {
        return err
    }

    if err := c.IDAuthSystem.Validate(validate); err != nil {
        return err
    }
    //...
}
```

Add initialization
```go
import (
    "github.com/digimaks/go-idauth"
)

func (a *App) InitServices() error {
    //...
    var err error
    a.systemTokenClient, err = idauth.NewSystemTokenClient(a.Config().IDAuthSystem)
    if err != nil {
        return err
    }
    //...
}
```

Add middleware for endpoints that need authentification

```go
import (
    "github.com/digimaks/go-idauth"
)

func Init(app *idauth.App) error {
    //...
    r.Use(idauth.Authentification(app.App, app.Config().IDAuth))
    //...
}
```

Call GetSystemToken to get system token

```go
import (
    "github.com/digimaks/go-idauth"
)

token, err = c.systemTokenClient.GetSystemToken(ctx, "scope:level")
```

Bind `/1.0/token` and `/1.0/session` endpoints

```go
import (
    "github.com/digimaks/go-idauth/authorization"
)

func Init(app *idauth.App) error {
    //...
	if err := authorization.Bind(r, a.Config().IDAuth); err != nil {
        return err
    }
    //...
}
```

`[POST] /1.0/token` endpoint example

No authorization header

`application/x-www-form-urlencoded`
```
grant_type: "authorization_code"
code: "01JN0TDJKGX87BGQVG01X1B48J"
code_verifier: "PesVLXxPtpQcf7FD8RzgkKnbwfE0pxIyokrnE2FbZ5s"
redirect_uri: "https://localhost:8888/auth-done"
```


`[GET] /1.0/session` endpoint example

Bearer token authorization header. Use the `access_token` from `/1.0/token` response


