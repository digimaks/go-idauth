// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

type Configuration struct {
	URL          string `mapstructure:"url" validate:"required,url"`
	ClientID     string `mapstructure:"client_id" validate:"required"`
	ClientSecret string `mapstructure:"client_secret" validate:"required"`
}

func (c *Configuration) Bind(prefix string, v *viper.Viper) {
	clientSecret, _ := config.LoadRemoteSecret("IDAUTH_CLIENT_SECRET")

	v.SetDefault(prefix+".client_secret", clientSecret)

	_ = v.BindEnv(prefix+".url", "IDAUTH_URL")
	_ = v.BindEnv(prefix+".client_id", "IDAUTH_CLIENT_ID")
	_ = v.BindEnv(prefix+".client_secret", "IDAUTH_CLIENT_SECRET")
}

// Validate IDAuth configuration section.
func (c *Configuration) Validate(valid *validation.Validate) error {
	return valid.Struct(c)
}
