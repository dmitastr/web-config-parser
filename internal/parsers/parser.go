package parsers

type Parser interface {
	Parse(content []byte) (interface{}, error)
}
