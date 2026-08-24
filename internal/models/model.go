package models

type Field struct {
}

type Config interface {
	GetField(name string) (*Field, error)
}
