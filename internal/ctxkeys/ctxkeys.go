package ctxkeys

type CtxKey string

const (
	UserAgentKey CtxKey = "user_agent"
	IPAddressKey CtxKey = "ip_address"
	ClaimsKey    CtxKey = "claims"
)
