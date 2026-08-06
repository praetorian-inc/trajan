package bitbucket

type TokenEnumerateResult struct {
	TokenInfo *TokenInfo     `json:"token_info"`
	User      *User          `json:"user,omitempty"`
	RateLimit *RateLimitInfo `json:"rate_limit,omitempty"`
	Errors    []string       `json:"errors,omitempty"`
}

type User struct {
	DisplayName   string `json:"display_name"`
	Username      string `json:"username"`
	UUID          string `json:"uuid"`
	AccountID     string `json:"account_id"`
	AccountStatus string `json:"account_status"`
	IsStaff       bool   `json:"is_staff"`
}

type RateLimitInfo struct {
	Limit     int  `json:"limit"`
	NearLimit bool `json:"near_limit"`
}
