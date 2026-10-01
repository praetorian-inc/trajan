package ado

import "strings"

func resourceSlug(s string) string {
	if strings.ContainsRune(s, '_') {
		return strings.ToLower(s)
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i := 0; i < len(s); i++ {
		c := s[i]
		upper := c >= 'A' && c <= 'Z'
		if upper && i > 0 && !(s[i-1] >= 'A' && s[i-1] <= 'Z') {
			b.WriteByte('_')
		}
		if upper {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}
