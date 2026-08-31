package models

// Result результат рабобты анализаторов
type Result struct {
	SourceName string     `json:"source_name"`
	Findings   []*Finding `json:"findings"`
	Error      error      `json:"error"`
}
