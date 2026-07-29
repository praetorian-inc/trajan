package engine

type Config struct {
	Concurrency int
	OutputDir   string
	Dev         bool
	Token       string // explicit API token from --token; overrides env when set
}
