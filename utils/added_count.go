package utils

var lastAddedCount = make(map[string]int)

// SetAddedCount stores how many dependencies a handler added
func SetAddedCount(handlerName string, count int) {
	lastAddedCount[handlerName] = count
}

// GetAddedCountForLastHandler retrieves the stored count
func GetAddedCountForLastHandler(handlerName string) int {
	if val, ok := lastAddedCount[handlerName]; ok {
		return val
	}
	return 0
}
