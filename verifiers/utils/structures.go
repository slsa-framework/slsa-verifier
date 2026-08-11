package utils

import "maps"

func MergeMaps[K comparable, V any](m1, m2 map[K]V) map[K]V {
	m := make(map[K]V, len(m1)+len(m2))
	maps.Copy(m, m2)
	maps.Copy(m, m1)
	return m
}
