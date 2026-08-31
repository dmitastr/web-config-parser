package models

type Result struct {
	Source   string
	Findings []*Finding
	Error    error
}
