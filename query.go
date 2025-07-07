package go_auth

type (
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

func (q QuerierValueResolver) Has(key string) bool {
	return q.Querier.Query(key) == ""
}

type CallbackInputParams struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

func getCallbackInputs(queryValues QueryValueResolver) CallbackInputParams {
	return CallbackInputParams{
		Code:  queryValues.Get("code"),
		State: queryValues.Get("state"),
	}
}
