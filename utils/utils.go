package utils

func NullTerminatedToStrings(b []byte) []string {
	var result []string
	for len(b) > 0 {
		for i := 0; i < len(b); i++ {
			if b[i] == 0 {
				result = append(result, string(b[:i]))
				b = b[i+1:]
				break
			}
		}
	}
	if len(result) > 0 {
		return result
	}
	return []string{string(b)}
}
