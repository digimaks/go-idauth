// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// SystemTokenConfiguration is the configuration with private key for the auth system middleware.
type SystemTokenConfiguration struct {
	URL string `mapstructure:"url" validate:"required,url"`
	// ClientID is the IDAuth client ID
	ClientID string `mapstructure:"client_id"`
	// Certificate in PEM format
	Certificate string `mapstructure:"certificate" validate:"required"`
}

// Bind configuration section.
func (c *SystemTokenConfiguration) Bind(prefix string, v *viper.Viper) {
	cert, _ := config.LoadRemoteSecret("IDAUTH_SYSTEM_CERTIFICATE")

	v.SetDefault(prefix+".certificate", cert)
	v.SetDefault(prefix+".client_id", "system")

	_ = v.BindEnv(prefix+".url", "IDAUTH_URL")
	_ = v.BindEnv(prefix+".client_id", "IDAUTH_SYSTEM_CLIENT_ID")
	_ = v.BindEnv(prefix+".certificate", "IDAUTH_SYSTEM_CERTIFICATE")
}

// Validate application configuration.
func (c *SystemTokenConfiguration) Validate(validate *validation.Validate) error {
	return validate.Struct(c)
}
