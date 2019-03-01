package rbac

import (
	"errors"
	"github.com/casbin/casbin/log"
	casbin_rbac "github.com/casbin/casbin/rbac"
	"regexp"
	"sync"
)

type MatchingFunc func(arg1, arg2 string) bool

// RoleManager provides a default implementation for the RoleManager interface. Based on default casbin role manager
// for RBAC with domains.
type RoleManager struct {
	allRoles          *sync.Map
	maxHierarchyLevel int
	matchingFunc      MatchingFunc
}

// NewRoleManager is the constructor for creating an instance of the
// default RoleManager implementation.
func NewRoleManager(maxHierarchyLevel int) casbin_rbac.RoleManager {
	rm := RoleManager{}
	rm.allRoles = &sync.Map{}
	rm.maxHierarchyLevel = maxHierarchyLevel
	rm.matchingFunc = BothSideMatchKeys

	return &rm
}

func (rm *RoleManager) hasRole(name string) bool {
	var ok bool

	rm.allRoles.Range(func(key, value interface{}) bool {
		if rm.matchingFunc(name, key.(string)) {
			ok = true
		}
		return true
	})

	return ok
}

func (rm *RoleManager) createRole(name string) *RbacRole {
	rm.allRoles.Range(func(key, value interface{}) bool {
		if rm.matchingFunc(name, key.(string)) {
			name = key.(string)
		}
		return true
	})

	role, _ := rm.allRoles.LoadOrStore(name, newRole(name))
	return role.(*RbacRole)
}

// Clear clears all stored data and resets the role manager to the initial state.
func (rm *RoleManager) Clear() error {
	rm.allRoles = &sync.Map{}
	return nil
}

// AddLink adds the inheritance link between role: name1 and role: name2.
// aka role: name1 inherits role: name2.
// domain is a prefix to the roles.
func (rm *RoleManager) AddLink(name1 string, name2 string, domain ...string) error {
	if len(domain) == 1 {
		name1 = domain[0] + "::" + name1
		name2 = domain[0] + "::" + name2
	} else if len(domain) > 1 {
		return errors.New("error: domain should be 1 parameter")
	}

	role1 := rm.createRole(name1)
	role2 := rm.createRole(name2)
	role1.addRole(role2)
	return nil
}

// DeleteLink deletes the inheritance link between role: name1 and role: name2.
// aka role: name1 does not inherit role: name2 any more.
// domain is a prefix to the roles.
func (rm *RoleManager) DeleteLink(name1 string, name2 string, domain ...string) error {
	if len(domain) == 1 {
		name1 = domain[0] + "::" + name1
		name2 = domain[0] + "::" + name2
	} else if len(domain) > 1 {
		return errors.New("error: domain should be 1 parameter")
	}

	if !rm.hasRole(name1) || !rm.hasRole(name2) {
		return errors.New("error: name1 or name2 does not exist")
	}

	role1 := rm.createRole(name1)
	role2 := rm.createRole(name2)
	role1.deleteRole(role2)
	return nil
}

// HasLink determines whether role: name1 inherits role: name2.
// domain is a prefix to the roles.
func (rm *RoleManager) HasLink(name1 string, name2 string, domain ...string) (bool, error) {
	if len(domain) == 1 {
		name1 = domain[0] + "::" + name1
		name2 = domain[0] + "::" + name2
	} else if len(domain) > 1 {
		return false, errors.New("error: domain should be 1 parameter")
	}

	if name1 == name2 {
		return true, nil
	}

	if !rm.hasRole(name1) || !rm.hasRole(name2) {
		return false, nil
	}

	role1 := rm.createRole(name1)
	return role1.hasRole(name2, rm.maxHierarchyLevel), nil
}

// GetRoles gets the roles that a subject inherits.
// domain is a prefix to the roles.
func (rm *RoleManager) GetRoles(name string, domain ...string) ([]string, error) {
	if len(domain) == 1 {
		name = domain[0] + "::" + name
	} else if len(domain) > 1 {
		return nil, errors.New("error: domain should be 1 parameter")
	}

	if !rm.hasRole(name) {
		return []string{}, nil
	}

	roles := rm.createRole(name).getRoles()
	if len(domain) == 1 {
		re := regexp.MustCompile(`^\*::(.+)$`)

		for i := range roles {
			// If we have domains like `*` we need to extract real role name
			// in different way.
			match := re.FindStringSubmatch(roles[i])
			if len(match) == 2 {
				roles[i] = match[1]
				continue
			} else {
				roles[i] = roles[i][len(domain[0])+2:]
			}
		}
	}
	return roles, nil
}

// GetUsers gets the users that inherits a subject.
// domain is an unreferenced parameter here, may be used in other implementations.
func (rm *RoleManager) GetUsers(name string, domain ...string) ([]string, error) {
	if len(domain) == 1 {
		name = domain[0] + "::" + name
	} else if len(domain) > 1 {
		return nil, errors.New("error: domain should be 1 parameter")
	}

	if !rm.hasRole(name) {
		return nil, errors.New("error: name does not exist")
	}

	names := []string{}
	rm.allRoles.Range(func(_, value interface{}) bool {
		role := value.(*RbacRole)
		if role.hasDirectRole(name) {
			names = append(names, role.name)
		}
		return true
	})
	if len(domain) == 1 {
		re := regexp.MustCompile(`^\*::(.+)$`)

		for i := range names {
			// If we have domains like `*` we need to extract real role name
			// in different way.
			match := re.FindStringSubmatch(names[i])
			if len(match) == 2 {
				names[i] = match[1]
			} else {
				names[i] = names[i][len(domain[0])+2:]
			}
		}
	}
	return names, nil
}

// PrintRoles prints all the roles to log.
func (rm *RoleManager) PrintRoles() error {
	line := ""
	rm.allRoles.Range(func(_, value interface{}) bool {
		if text := value.(*RbacRole).toString(); text != "" {
			if line == "" {
				line = text
			} else {
				line += ", " + text
			}
		}
		return true
	})
	log.LogPrint(line)
	return nil
}

// RbacRole represents the data structure for a role in RBAC.
type RbacRole struct {
	name  string
	roles []*RbacRole
}

func newRole(name string) *RbacRole {
	r := RbacRole{}
	r.name = name
	return &r
}

func (r *RbacRole) addRole(role *RbacRole) {
	for _, rr := range r.roles {
		if rr.name == role.name {
			return
		}
	}

	r.roles = append(r.roles, role)
}

func (r *RbacRole) deleteRole(role *RbacRole) {
	for i, rr := range r.roles {
		if rr.name == role.name {
			r.roles = append(r.roles[:i], r.roles[i+1:]...)
			return
		}
	}
}

func (r *RbacRole) hasRole(name string, hierarchyLevel int) bool {
	if BothSideMatchKeys(name, r.name) {
		return true
	}

	if r.name == name {
		return true
	}

	if hierarchyLevel <= 0 {
		return false
	}

	for _, role := range r.roles {
		if role.hasRole(name, hierarchyLevel-1) {
			return true
		}
	}
	return false
}

func (r *RbacRole) hasDirectRole(name string) bool {
	// We need to check both direct match and wildcard match.
	for _, role := range r.roles {
		if role.name == name {
			return true
		} else if BothSideMatchKeys(role.name, name) {
			return true
		}
	}

	return false
}

func (r *RbacRole) toString() string {
	names := ""
	if len(r.roles) == 0 {
		return ""
	}
	for i, role := range r.roles {
		if i == 0 {
			names += role.name
		} else {
			names += ", " + role.name
		}
	}

	if len(r.roles) == 1 {
		return r.name + " < " + names
	} else {
		return r.name + " < (" + names + ")"
	}
}

func (r *RbacRole) getRoles() []string {
	names := []string{}
	for _, role := range r.roles {
		names = append(names, role.name)
	}
	return names
}
