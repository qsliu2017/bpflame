package bpf

// Map maps from cookie to probe name.
type Map struct {
	m map[uint64]string
}

// NewMap creates a new Map.
func NewMap(probeNames []string) *Map {
	m := &Map{
		m: make(map[uint64]string, len(probeNames)*2),
	}
	for i, name := range probeNames {
		m.m[uint64(i)<<1] = name
		m.m[uint64(i)<<1+1] = name
	}
	return m
}

// Get returns the probe name and isRet for the given cookie.
func (m *Map) Get(cookie uint64) (name string, isRet bool) {
	name, isRet = m.m[cookie], cookie&1 == 1
	return
}

// NCookies returns the number of cookies.
func (m *Map) NCookies() int {
	return len(m.m)
}
