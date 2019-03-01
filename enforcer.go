package rbac

import (
	"fmt"
	"github.com/casbin/casbin"
	"github.com/casbin/casbin/model"
	"github.com/casbin/casbin/persist"
	casbin_rbac "github.com/casbin/casbin/rbac"
	"strings"
)

const (
	// AllowAccess should be used as effect for policies that allow access.
	AllowAccess = "allow"

	// SkipResourceId should be used for policies that should skip
	// resource identity check in permissions.
	SkipResourceId = "skip"

	permissionOwner      = 0
	permissionRole       = 1
	permissionResourceId = 2
	maxHierarchyLevel    = 3
)

// CustomFunction used to add custom functions to match.
type CustomFunction func(args ...interface{}) (interface{}, error)

// Enforcer. By default role modelText in Qilin role manager works with RBAC with domains for all users.
// We also uses elements of ABAC to check specific policy rules for resources and users.
type Enforcer struct {
	roleManager casbin_rbac.RoleManager
	enforcer    *casbin.SyncedEnforcer
}

// Context used to identity enforce request.
type Context struct {
	User          string `json:"user"`
	Domain        string `json:"domain"`
	Resource      string `json:"resource"`
	ResourceId    string `json:"resourceId"`
	ResourceOwner string `json:"resourceOwner"`
	Action        string `json:"action"`
}

// Role used to add new roles for user with given restrictions to resource.
type Role struct {
	User                 string   `json:"user"`
	Role                 string   `json:"role"`
	Domain               string   `json:"domain"`
	Owner                string   `json:"owner"`
	RestrictedResourceId []string `json:"restrictedResourceId"`
}

// Policy used to declare new RBAC model policy in casbin.
type Policy struct {
	Role         string `json:"role"`
	Domain       string `json:"domain"`
	ResourceType string `json:"resourceType"`
	ResourceId   string `json:"resourceId"`
	Action       string `json:"action"`
	Effect       string `json:"effect"`
}

// Restriction define one permission rule.
type Restriction struct {
	Owner string `json:"owner"`
	Role  string `json:"rols"`
	UUID  string `json:"uuid"`
}

// UserPermissions  contains detailed information about user roles and permissions.
type UserPermissions struct {
	User                  string            `json:"user"`
	Domain                string            `json:"domain"`
	Permissions           []*UserPermission `json:"permissions"`
	UnmatchedRestrictions []*Restriction    `json:"unmatchedRestrictions"`
}

// UserPermission defines a single permission.
type UserPermission struct {
	Role     string `json:"role"`
	Domain   string `json:"domain"`
	Resource string `json:"resource"`
	UUID     string `json:"uuid"`
	Action   string `json:"action"`
	Allowed  bool   `json:"allowed"`
	// Restrictions  defines all permissions and restriction for given user and role.
	Restrictions []*Restriction `json:"restrictions"`
}

// Enforcer create and init then Enforcer instance.
func NewEnforcer(params ...interface{}) *Enforcer {
	rm := &Enforcer{}

	m := casbin.NewModel(modelText)

	if len(params) == 1 {
		switch p0 := params[0].(type) {
		case *casbin.SyncedEnforcer:
			rm.enforcer = p0
			return rm
		case persist.Adapter:
			rm.createEnforcer(m, p0)
		case model.Model:
			rm.createEnforcer(m, nil)
		default:
			panic("Unknown parameter type for Enforcer.")
		}
	} else if len(params) == 2 {
		switch p0 := params[0].(type) {
		case persist.Adapter:
			rm.createEnforcer(m, p0)
		default:
			panic("Invalid parameters for enforcer.")
		}

		switch p1 := params[1].(type) {
		case persist.Watcher:
			rm.enforcer.SetWatcher(p1)
		default:
			panic("Invalid parameters for enforcer.")
		}
	} else if len(params) == 0 {
		rm.createEnforcer(m, nil)
	} else {
		panic("Invalid parameters for enforcer.")
	}

	return rm
}

func (rm *Enforcer) createEnforcer(m model.Model, a persist.Adapter) {
	rm.enforcer = casbin.NewSyncedEnforcer()
	rm.enforcer.InitWithModelAndAdapter(m, a)

	rm.roleManager = NewRoleManager(maxHierarchyLevel)

	// If creating enforser with our own we redeclare internal role manager to custom role manager
	// which support wildcard check for domain based `g` function.
	//
	// Example:
	// p, role, domain/*, obj
	// g, alise, role, domain/*
	// r, alise, domain/5, obj
	//
	// g(r.sub, p.sub, r.dom) -> true
	rm.enforcer.SetRoleManager(rm.roleManager)

	// We need rebuild it forcibly due to casbin internal initialization realization.
	rm.enforcer.BuildRoleLinks()

	rm.enforcer.AddFunction("has_access_to_resource", rm.hasAccessToResource)
	rm.enforcer.AddFunction("matchKeys", MatchKeysFunc)
	rm.enforcer.AddFunction("bothSideMatchKeys", BothSideMatchKeysFunc)
}

// AddFunction adds a customized function.
func (rm *Enforcer) AddFunction(name string, function CustomFunction) {
	rm.enforcer.AddFunction(name, function)
}

// Enforce decides whether a "subject" in "domain" can access a "resource" with the operation "action",
// input parameters are usually: (subject, domain, resource, action).
func (rm *Enforcer) Enforce(pr Context) bool {
	return rm.enforcer.Enforce(pr)
}

// AddPolicy adds an authorization rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (rm *Enforcer) AddPolicy(p Policy) bool {
	return rm.enforcer.AddPolicy(
		p.Role,
		p.Domain,
		p.ResourceType,
		p.ResourceId,
		p.Action,
		p.Effect,
	)
}

// RemovePolicy removes an authorization rule from the current policy.
func (rm *Enforcer) RemovePolicy(p Policy) bool {
	return rm.enforcer.RemovePolicy(
		p.Role,
		p.Domain,
		p.ResourceType,
		p.ResourceId,
		p.Action,
		p.Effect,
	)
}

// LinkRoles adds a role inheritance rule to the current policy in domain.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (rm *Enforcer) LinkRoles(role1, role2, domain string) bool {
	return rm.enforcer.AddGroupingPolicy(role1, role2, domain)
}

// UnlinkRoles removes a role inheritance rule from the current policy in domain.
// If the rule not exists, the function returns false and the rule will not be deleted.
// Otherwise the function returns true by deleting the rule.
func (rm *Enforcer) UnlinkRoles(role1, role2, domain string) bool {
	return rm.enforcer.RemoveGroupingPolicy(role1, role2, domain)
}

// HasLink determines whether a role inheritance rule exists.
func (rm *Enforcer) HasLink(role1, role2, domain string) bool {
	return rm.enforcer.HasGroupingPolicy(role1, role2, domain)
}

// AddRole adds a role for a user inside a domain with given permissions.
// Returns false if the user already has the role (aka not affected).
func (rm *Enforcer) AddRole(rr Role) bool {
	for _, r := range rr.RestrictedResourceId {
		rm.AddRestrictionToUser(rr.User, &Restriction{rr.Owner, rr.Role, r})
	}

	return rm.enforcer.AddRoleForUserInDomain(rr.User, rr.Role, rr.Domain)
}

// RemoveRole deletes a role for a user inside a domain.
// Returns false if the user does not have the role (aka not affected).
func (rm *Enforcer) RemoveRole(rr Role) bool {
	for _, r := range rr.RestrictedResourceId {
		rm.RemoveRestrictionFromUser(rr.User, &Restriction{rr.Owner, rr.Role, r})
	}
	return rm.enforcer.DeleteRoleForUserInDomain(rr.User, rr.Role, rr.Domain)
}

// DeleteUser deletes a user.
// Returns false if the user does not exist (aka not affected).
func (rm *Enforcer) DeleteUser(user string) bool {
	rm.enforcer.RemoveFilteredNamedGroupingPolicy("g2", 0, user)
	return rm.enforcer.RemoveFilteredGroupingPolicy(0, user)
}

// AddRestrictionToUser add the resource identity to `g2` grouping policy. This used to
// implement access filtering for special resources in domain role. By default each role in domain
// have full access to all resources in domain. This restrictions allow to restrict access just for
// given resources.
func (rm *Enforcer) AddRestrictionToUser(user string, r *Restriction) bool {
	return rm.enforcer.AddNamedGroupingPolicy("g2", user, r.GetRaw())
}

// RemoveRestrictionFromUser removes a role inheritance rule from the `g2` named policy.
func (rm *Enforcer) RemoveRestrictionFromUser(user string, r *Restriction) bool {
	return rm.enforcer.RemoveNamedGroupingPolicy("g2", user, r.GetRaw())
}

// GetUserRestrictions return unassigned list of restrictions
func (rm *Enforcer) GetUserRestrictions(user string) []*Restriction {
	var data []*Restriction
	res := rm.enforcer.GetFilteredNamedGroupingPolicy("g2", 0, user)
	for _, n := range res {
		data = append(data, rm.createUserRestriction(n[1]))
	}

	return data
}

// GetUsersForRole gets the users that has a role inside a domain with given filtering. By default
// you could provide onwer, role and uuid as string of pass *Restriction to check.
func (rm *Enforcer) GetUsersForRole(role string, domain string, filters ...interface{}) []string {
	users := rm.enforcer.GetUsersForRoleInDomain(role, domain)
	if len(filters) == 0 {
		return users
	}

	var restrictionFilter *Restriction
	switch filters[0].(type) {
	case *Restriction:
		restrictionFilter = filters[0].(*Restriction)
	case string:
		restrictionFilter = &Restriction{Owner: filters[0].(string)}
		if len(filters) >= 2 {
			switch filters[1].(type) {
			case string:
				restrictionFilter.Role = filters[1].(string)
			}
		}

		if len(filters) == 3 {
			switch filters[2].(type) {
			case string:
				restrictionFilter.UUID = filters[2].(string)
			}
		}
	default:
		panic(fmt.Sprintf("Invalid arguments in filter %+v", filters))
	}

	var filteredUsers []string
	for _, u := range users {
		userRestrictions := rm.GetUserRestrictions(u)
		if len(userRestrictions) == 0 {
			filteredUsers = append(filteredUsers, u)
			continue
		}

		for _, r := range userRestrictions {
			if restrictionFilter.UUID != "" && restrictionFilter.UUID != r.UUID {
				continue
			}

			if restrictionFilter.Role != "" && restrictionFilter.Role != r.Role {
				continue
			}

			if restrictionFilter.Owner != r.Owner {
				continue
			}
			filteredUsers = append(filteredUsers, u)
		}
	}

	return filteredUsers
}

// GetRolesForUser gets the roles that a user has inside a domain.
func (rm *Enforcer) GetRolesForUser(user, domain string) []string {
	return rm.enforcer.GetRolesForUserInDomain(user, domain)
}

// GetPermissionsForUser returns all the allow and deny permissions for a user
func (rm *Enforcer) GetPermissionsForUser(user, domain string) *UserPermissions {
	up := UserPermissions{
		User:   user,
		Domain: domain,
	}

	subjects := rm.enforcer.GetRolesForUserInDomain(user, domain)
	subjects = append(subjects, user)

	up.Permissions = rm.buildPermissions(subjects, domain)

	unmatchedPerms := make(map[string]bool)
	for _, r := range rm.GetUserRestrictions(user) {
		for _, p := range up.Permissions {
			if rm.matchRestriction(r.GetRaw(), r.Owner, p.Role, p.Domain, SkipResourceId, SkipResourceId) {
				p.Restrictions = append(p.Restrictions, r)
			} else {
				key := r.Owner + r.Role + r.UUID
				if _, ok := unmatchedPerms[key]; !ok {
					unmatchedPerms[key] = true
					up.UnmatchedRestrictions = append(up.UnmatchedRestrictions, r)
				}
			}
		}
	}

	return &up
}

func (rm *Enforcer) buildPermissions(subjects []string, domain string) []*UserPermission {
	var permissions []*UserPermission

	perms := make(map[string]*UserPermission)
	for _, subject := range subjects {
		for _, p := range rm.enforcer.GetPermissionsForUserInDomain(subject, domain) {
			permission := &UserPermission{Role: p[0], Domain: p[1], Resource: p[2], UUID: p[3], Action: p[4], Allowed: p[5] == AllowAccess}
			key := permission.Role + permission.Domain + permission.Resource + permission.UUID + permission.Action
			if _, ok := perms[key]; !ok {
				perms[key] = permission
				permissions = append(permissions, permission)
			}
		}
	}

	return permissions
}

func (rm *Enforcer) createUserRestriction(res string) *Restriction {
	parts := strings.Split(res, "/")

	switch len(parts) {
	case 1:
		return &Restriction{parts[0], "", ""}
	case 2:
		return &Restriction{parts[0], parts[1], ""}
	case 3:
		return &Restriction{parts[0], parts[1], parts[2]}
	}

	panic("Can`t create Restriction with given res")
}

func (rm *Enforcer) hasAccessToResource(args ...interface{}) (interface{}, error) {
	pr := args[0].(Context)

	res := rm.enforcer.GetFilteredNamedGroupingPolicy("g2", 0, pr.User)
	if len(res) == 0 {
		return true, nil
	}

	policyRole := args[1].(string)
	policyUUID := args[2].(string)

	for _, n := range res {
		if rm.matchRestriction(n[1], pr.ResourceOwner, policyRole, pr.Domain, policyUUID, pr.ResourceId) {
			return true, nil
		}
	}
	return false, nil
}

func (rm *Enforcer) matchRestriction(res, owner, policyRole, domain, policyUUID, resourceId string) bool {
	ok := false

	parts := strings.Split(res, "/")
	if len(parts) >= 1 {
		ok = MatchKeys(owner, parts[permissionOwner])
	}

	if len(parts) >= 2 && parts[permissionRole] != "*" {
		matchRole, err := rm.roleManager.HasLink(parts[permissionRole], policyRole, domain)
		ok = ok && matchRole && err == nil
	}

	if len(parts) == 3 && policyUUID != SkipResourceId {
		ok = ok && MatchKeys(resourceId, parts[permissionResourceId])
	}

	return ok
}

// GetRaw return raw string for permission in `g2`
func (ur *Restriction) GetRaw() string {
	if ur.Role == "" {
		return ur.Owner
	}

	if ur.UUID == "" {
		return ur.Owner + "/" + ur.Role
	}

	return ur.Owner + "/" + ur.Role + "/" + ur.UUID
}
