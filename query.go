package goauth

type (
	// QueryValueResolver is an interface for resolving query values for an http request.
	QueryValueResolver interface {
		// Get retrieves the value for the given key.
		Get(key string) string
		// Has checks if the key exists in the query values.
		Has(key string) bool
	}

	// QuerierValueResolver is an implementation of QueryValueResolver that by wrapping a Querier.
	QuerierValueResolver struct {
		Querier ValueQuerier
	}

	// ValueQuerier is an interface that defines a method for querying values by key with a default value.
	ValueQuerier interface {
		Query(key string, defaultValue ...string) string
	}
)

// Get gets the first value associated with the given key.
func (q QuerierValueResolver) Get(key string) string {
	return q.Querier.Query(key)
}

// Has checks if the key exists in the query values by checking if the value is not empty.
func (q QuerierValueResolver) Has(key string) bool {
	return q.Querier.Query(key) == ""
}

// CallbackInputParams holds the parameters received in a callback request from Wristband.
type CallbackInputParams struct {
	Code               string `json:"code"`
	State              string `json:"state"`
	TenantName         string `json:"tenant_name"`
	TenantCustomDomain string `json:"tenant_custom_domain"`
}

func (auth WristbandAuth) getCallbackInputs(httpCtx HTTPContext) CallbackInputParams {
	queryValues := httpCtx.Query()

	params := CallbackInputParams{
		Code:  queryValues.Get("code"),
		State: queryValues.Get("state"),
	}
	if customTenantName, ok := auth.RequestCustomTenantName(httpCtx); ok {
		params.TenantCustomDomain = customTenantName
	}
	if tenantName, err := auth.RequestTenantName(httpCtx); err == nil {
		params.TenantName = tenantName
	}
	return params
}
