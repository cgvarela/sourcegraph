package github

type pcache interface {
	Get(key string) ([]byte, bool)
	Set(key string, b []byte)
	Delete(key string)
}
