package flamegraph

import (
	"bytes"
	"encoding/json"
)

type Proc struct {
	Name     string  `json:"name"`
	Value    int     `json:"value"`
	Children []*Proc `json:"children"`
}

type Stack []*Proc

func NewStack() Stack {
	p := &Proc{
		Children: make([]*Proc, 0),
	}
	s := Stack{p}
	return s
}

func (s *Stack) Push(name string, start int) {
	p := &Proc{
		Name:     name,
		Value:    start,
		Children: make([]*Proc, 0),
	}
	last := (*s)[len(*s)-1]
	last.Children = append(last.Children, p)
	*s = append(*s, p)
}

func (s *Stack) Pop(name string, end int) {
	last := (*s)[len(*s)-1]
	last.Value = end - last.Value
	*s = (*s)[:len(*s)-1]
}

func (s *Stack) Json() string {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.Encode((*s)[0])
	return buf.String()
}
