package models

type Source struct {
	Path    string
	Content any
	Finding []*Finding
}
