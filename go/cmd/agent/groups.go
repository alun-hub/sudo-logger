package main

import (
	"log"
	"os/user"
)

// resolveUserGroups returns the names of all groups the given username belongs
// to, resolved via the OS NSS stack (works with local /etc/group, SSSD, LDAP,
// winbind, etc.).  Returns nil on any error so a lookup failure is non-fatal.
func resolveUserGroups(username string) []string {
	u, err := user.Lookup(username)
	if err != nil {
		log.Printf("groups: lookup %q: %v", username, err)
		return nil
	}
	gids, err := u.GroupIds()
	if err != nil {
		log.Printf("groups: GroupIds for %q: %v", username, err)
		return nil
	}
	names := make([]string, 0, len(gids))
	for _, gid := range gids {
		g, err := user.LookupGroupId(gid)
		if err != nil {
			continue
		}
		names = append(names, g.Name)
	}
	return names
}
