// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"strconv"
	"time"

	"azugo.io/azugo/token"
)

// UserinfoResponse is the response body for the userinfo endpoint data.
type UserinfoResponse struct {
	// SessionID is the session identifier
	SessionID string `json:"sid,omitempty" validate:"omitempty,len=26" example:"01FMG08GHT6QJE32XHGVMWB82D"`
	// Active is the session active flag
	Active bool `json:"active"`
	// UserID is unique user identifier
	UserID string `json:"sub,omitempty" validate:"required,min=1,max=20" example:"PNOXX-111111-11111"`
	// Code is unique person identifier
	Code string `json:"code,omitempty" validate:"required,min=1,max=20" example:"11111111111"`
	// GivenName is the authorized users given name
	GivenName string `json:"given_name,omitempty" validate:"omitempty,max=100" example:"Jānis"`
	// FamilyName is the authorized users family name
	FamilyName string `json:"family_name,omitempty" validate:"omitempty,max=200" example:"Testiņš"`
	// OrganizationName is the authorized users organization name (AuthorityFullName)
	OrganizationName string `json:"org_name,omitempty" validate:"omitempty,max=250" example:"Testiņa uzņēmums"`
	// OrganizationCode is the authorized users organization code (URAuthorityCode)
	OrganizationCode string `json:"org_id,omitempty" validate:"omitempty,max=50" example:"11111111111"`

	// TODO: move to session state struct
	// State is the session state
	State string `json:"st" validate:"required,oneof=none req_agreement req_role authorized" example:"authorized"`
	// Scope is the list of user rights
	Scope []string `json:"scope,omitempty" validate:"omitempty,dive,required,min=1,max=60" example:"[\"admin/settings:read\"]"`
	// Session timeout in seconds
	SecondsToLive int `json:"secondsToLive"`
	// Seconds before session expiration when session countdown should appear
	SecondsToCountdown int `json:"secondsToCountdown"`
	// IsSessionExtendable is the flag if session can be extended with keep-alive request
	IsSessionExtendable bool `json:"isSessionExtendable"`
}

func (s *UserinfoResponse) ToClaims() map[string]token.ClaimStrings {
	claims := map[string]token.ClaimStrings{
		"sid":         {s.SessionID},
		"sub":         {s.UserID},
		"code":        {s.Code},
		"given_name":  {s.GivenName},
		"family_name": {s.FamilyName},
		"scope":       s.Scope,
		"exp":         {strconv.FormatUint(uint64(time.Now().UTC().Unix())+uint64(s.SecondsToLive), 10)}, //#nosec G115
		"org_id":      {s.OrganizationCode},
		"org_name":    {s.OrganizationName},
	}

	return claims
}
