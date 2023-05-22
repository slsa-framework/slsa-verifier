package utils

func MergeMaps[K comparable, V any](m1, m2 map[K]V) map[K]V {
	m := make(map[K]V, len(m1)+len(m2))
	for k, v := range m2 {
		m[k] = v
	}
	for k, v := range m1 {
		m[k] = v
	}
	return m
}
