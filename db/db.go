package db

func GetCustomPermissions(userID string) []string {
	if userID == "123" {
		return []string{"card:write"}
	}

	return []string{}
}

func GetOwnershipData(userID string, cardId string) bool {
	if userID == "345" {
		return true
	}

	return false
}
