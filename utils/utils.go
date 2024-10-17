package utils

func Roundup(x, bound int) int {
	return (x + (bound - 1)) &^ (bound - 1)
}
