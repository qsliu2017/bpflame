package bpf

// Map maps from cookie to probe name.
type Map map[uint64]string

// NewMap creates a new Map.
func NewMap(probeNames []string) Map {
	m := make(Map, len(probeNames)*2)
	for i, name := range probeNames {
		m[uint64(i)<<1] = name
		m[uint64(i)<<1+1] = name
	}
	return m
}

// Get returns the probe name and isRet for the given cookie.
func (m Map) Get(cookie uint64) (name string, isRet bool) {
	name, isRet = m[cookie], cookie&1 == 1
	return
}

// NCookies returns the number of cookies.
func (m Map) NCookies() int {
	return len(m)
}
