package config

import "strings"

// DragonManagers are archive-scannable moderation modes. Docker images and
// Git repositories use different transport and are deliberately excluded.
var DragonManagers = []string{
	"pypi", "npm", "go", "nuget", "conan", "luarocks", "maven", "php", "terraform", "files",
}

func DragonRepositoryKey(manager string) string {
	return "DRAGON_REPOSITORY_ID_" + strings.ToUpper(manager)
}

func dragonRepositoryIDs(getenv func(string) string) map[string]string {
	ids := make(map[string]string, len(DragonManagers))
	for _, manager := range DragonManagers {
		ids[manager] = strings.TrimSpace(getenv(DragonRepositoryKey(manager)))
	}
	return ids
}

// DragonRepositoryFor never routes a package to a different manager's repo.
// The legacy unsuffixed setting is accepted for Go only.
func (c *Config) DragonRepositoryFor(manager string) string {
	manager = strings.ToLower(strings.TrimSpace(manager))
	if id := strings.TrimSpace(c.DragonRepositoryIDs[manager]); id != "" {
		return id
	}
	if manager == "go" {
		return strings.TrimSpace(c.DragonRepositoryID)
	}
	return ""
}

func (c *Config) HasDragonRepository() bool {
	for _, manager := range DragonManagers {
		if c.DragonRepositoryFor(manager) != "" {
			return true
		}
	}
	return false
}
