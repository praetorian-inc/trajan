package engine

type Config struct {
	Concurrency int
	OutputDir   string
	Dev         bool
	Token       string // explicit --token; env vars outrank this
	BearerToken string // explicit --azure-bearer-token; env vars outrank this
}
