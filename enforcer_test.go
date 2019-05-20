package rbac

import (
	"github.com/billcobbler/casbin-redis-watcher"
	"github.com/casbin/casbin"
	"github.com/casbin/casbin/persist/file-adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"testing"
)

func TestEnforcer_AddPolicy(t *testing.T) {
	enf := NewEnforcer()

	enf.AddPolicy(Policy{"admin", "vendor", "game", "*", "any", "allow"})
	enf.AddPolicy(Policy{"support", "vendor", "events", "skip", "any", "allow"})

	enf.AddRole(Role{"stan", "admin", "vendor", "alise", nil})
	enf.AddRole(Role{"brad", "support", "vendor", "alise", nil})

	testEnforceSync(t, enf, "stan", "vendor", "game", "1", "alise", "read", true)
	testEnforceSync(t, enf, "stan", "vendor", "events", "1", "alise", "read", false)
	testEnforceSync(t, enf, "brad", "vendor", "game", "1", "alise", "read", false)
	testEnforceSync(t, enf, "brad", "vendor", "events", "1", "alise", "read", true)

	enf.LinkRoles("admin", "support", "vendor")

	testEnforceSync(t, enf, "stan", "vendor", "game", "1", "alise", "read", true)
	testEnforceSync(t, enf, "stan", "vendor", "events", "1", "alise", "read", true)
	testEnforceSync(t, enf, "brad", "vendor", "game", "1", "alise", "read", false)
	testEnforceSync(t, enf, "brad", "vendor", "events", "1", "alise", "read", true)
}

func TestEnforcer_RemovePolicy(t *testing.T) {
	enf := NewEnforcer()

	policy := Policy{"admin", "vendor", "game", "*", "any", "allow"}

	enf.AddPolicy(policy)
	enf.AddRole(Role{"stan", "admin", "vendor", "alise", nil})

	testEnforceSync(t, enf, "stan", "vendor", "game", "1", "alise", "read", true)
	assert.True(t, enf.RemovePolicy(policy))
	assert.False(t, enf.RemovePolicy(policy))

	testEnforceSync(t, enf, "stan", "vendor", "game", "1", "alise", "read", false)
}

func TestEnforcer_LinkRoles(t *testing.T) {
	enf := NewEnforcer()
	enf.AddPolicy(Policy{"admin", "vendor", "game", "*", "any", "allow"})
	enf.AddPolicy(Policy{"support", "vendor", "events", "skip", "any", "allow"})
	enf.AddRole(Role{"stan", "admin", "vendor", "alise", nil})

	assert.True(t, enf.LinkRoles("admin", "support", "vendor"))
	assert.False(t, enf.LinkRoles("admin", "support", "vendor"))
}

func TestEnforcer_UnlinkRoles(t *testing.T) {
	enf := NewEnforcer()
	enf.AddPolicy(Policy{"admin", "vendor", "game", "*", "any", "allow"})
	enf.AddPolicy(Policy{"support", "vendor", "events", "skip", "any", "allow"})
	enf.AddRole(Role{"stan", "admin", "vendor", "alise", nil})
	enf.LinkRoles("admin", "support", "vendor")

	assert.True(t, enf.HasLink("admin", "support", "vendor"))
	testEnforceSync(t, enf, "stan", "vendor", "events", "1", "alise", "read", true)

	assert.True(t, enf.UnlinkRoles("admin", "support", "vendor"))
	assert.False(t, enf.UnlinkRoles("admin", "support", "vendor"))

	assert.False(t, enf.HasLink("admin", "support", "vendor"))
	testEnforceSync(t, enf, "stan", "vendor", "events", "1", "alise", "read", false)
}

func TestEnforcer_AddRole(t *testing.T) {
	enf := NewEnforcer()

	enf.AddPolicy(Policy{"admin", "vendor", "game", "*", "any", "allow"})
	enf.AddPolicy(Policy{"support", "vendor", "events", "*", "any", "allow"})
	enf.AddPolicy(Policy{"support", "vendor", "posts", "skip", "any", "allow"})
	enf.LinkRoles("admin", "support", "vendor")

	assert.True(t, enf.AddRole(Role{"stan", "admin", "vendor", "alise", []string{"50"}}))
	assert.True(t, enf.AddRole(Role{"brad", "support", "vendor", "alise", []string{"10"}}))

	testEnforceSync(t, enf, "stan", "vendor", "game", "1", "alise", "read", false)
	testEnforceSync(t, enf, "stan", "vendor", "events", "1", "alise", "read", false)
	testEnforceSync(t, enf, "brad", "vendor", "game", "1", "alise", "read", false)
	testEnforceSync(t, enf, "brad", "vendor", "events", "1", "alise", "read", false)

	testEnforceSync(t, enf, "stan", "vendor", "game", "50", "alise", "read", true)
	testEnforceSync(t, enf, "stan", "vendor", "events", "50", "alise", "read", true)
	testEnforceSync(t, enf, "brad", "vendor", "game", "50", "alise", "read", false)
	testEnforceSync(t, enf, "brad", "vendor", "events", "50", "alise", "read", false)

	testEnforceSync(t, enf, "stan", "vendor", "game", "10", "alise", "read", false)
	testEnforceSync(t, enf, "stan", "vendor", "events", "10", "alise", "read", false)
	testEnforceSync(t, enf, "brad", "vendor", "game", "10", "alise", "read", false)
	testEnforceSync(t, enf, "brad", "vendor", "events", "10", "alise", "read", true)

	testEnforceSync(t, enf, "stan", "vendor", "posts", "1", "alise", "read", true)
	testEnforceSync(t, enf, "stan", "vendor", "posts", "1", "alise", "write", true)
	testEnforceSync(t, enf, "brad", "vendor", "posts", "1", "alise", "read", true)
	testEnforceSync(t, enf, "brad", "vendor", "posts", "1", "alise", "read", true)

	assert.True(t, enf.AddRole(Role{"roman", "support", "vendor", "alise", []string{"*"}}))
	assert.True(t, enf.AddRole(Role{"roman", "support", "vendor", "brad", []string{"*"}}))
}

func TestEnforcer_RemoveRole(t *testing.T) {
	enf := NewEnforcer()

	role := Role{"stan", "admin", "vendor", "alise", []string{"50"}}

	enf.AddPolicy(Policy{"admin", "vendor", "game", "*", "any", "allow"})
	enf.AddRole(role)

	testEnforceSync(t, enf, "stan", "vendor", "game", "50", "alise", "read", true)
	assert.True(t, enf.RemoveRole(role))
	assert.False(t, enf.RemoveRole(role))

	testEnforceSync(t, enf, "stan", "vendor", "game", "50", "alise", "read", false)
}

func TestEnforcer_DeleteUser(t *testing.T) {
	enf := NewEnforcer()
	enf.AddPolicy(Policy{"admin", "vendor", "game", "*", "any", "allow"})
	enf.AddRole(Role{"stan", "admin", "vendor", "alise", []string{"50"}})

	assert.True(t, enf.DeleteUser("stan"))
	assert.False(t, enf.DeleteUser("stan"))

	testEnforceSync(t, enf, "stan", "vendor", "game", "50", "alise", "read", false)
	testGetRoleForUser(t, enf, []string{}, "stan", "vendor")
	testGetUsersForRole(t, enf, []string{}, "admin", "vendor")
}

func TestEnforcer_EnforceWithPermissions(t *testing.T) {
	Copy("./conf/restrict_policy.csv", "./conf/copy_restrict_policy.csv")
	a := fileadapter.NewAdapter("./conf/copy_restrict_policy.csv")
	enf := NewEnforcer(a)

	testEnforceSync(t, enf, "max", "vendor", "games", "1", "alise", "read", true)
	testEnforceSync(t, enf, "max", "vendor", "social", "1", "alise", "read", true)
	testEnforceSync(t, enf, "max", "vendor", "statistic", "1", "alise", "read", true)

	testEnforceSync(t, enf, "tony", "vendor", "games", "1", "alise", "read", false)
	testEnforceSync(t, enf, "tony", "vendor", "social", "1", "alise", "read", true)
	testEnforceSync(t, enf, "tony", "vendor", "statistic", "1", "alise", "read", false)

	testEnforceSync(t, enf, "fred", "vendor", "games", "1", "alise", "read", false)
	testEnforceSync(t, enf, "fred", "vendor", "social", "1", "alise", "read", false)
	testEnforceSync(t, enf, "fred", "vendor", "statistic", "5", "alise", "read", true)
}

func TestEnforcer_Enforce(t *testing.T) {
	Copy("./conf/keymatch_policy.csv", "./conf/copy_keymatch_policy.csv")
	a := fileadapter.NewAdapter("./conf/copy_keymatch_policy.csv")
	enf := NewEnforcer(a)

	enf.AddRole(Role{Role: "admin", User: "superman", Domain: "vendor", Owner: "alise", RestrictedResourceId: []string{"*"}})
	testEnforceSync(t, enf, "superman", "vendor", "games", "any", "another_owner", "read", false)
	testEnforceSync(t, enf, "superman", "vendor", "games", "any", "alise", "read", true)

	testEnforceSync(t, enf, "alise", "vendor", "any resource", "1", "alise", "read", true)
	testEnforceSync(t, enf, "alise", "vendor", "any resource", "1", "alise", "write", true)
	testEnforceSync(t, enf, "alise", "vendor", "any resource", "1", "max", "read", false)
	testEnforceSync(t, enf, "alise", "vendor", "any resource", "1", "max", "write", false)

	testEnforceSync(t, enf, "max", "vendor", "games", "1", "alise", "read", true)
	testEnforceSync(t, enf, "max", "vendor", "games", "1", "alise", "write", true)
	testEnforceSync(t, enf, "max", "vendor", "statistic", "1", "alise", "write", true)

	testEnforceSync(t, enf, "max", "vendor", "price", "1", "alise", "read", true)
	testEnforceSync(t, enf, "max", "vendor", "price", "1", "alise", "write", false)
	testEnforceSync(t, enf, "max", "merch", "games", "1", "alise", "read", false)
	testEnforceSync(t, enf, "max", "*", "games", "1", "alise", "read", false)
	testEnforceSync(t, enf, "max", "vendor", "bundle", "1", "alise", "create", true)
	testEnforceSync(t, enf, "max", "vendor", "bundle", "1", "alise", "read", true)
	testEnforceSync(t, enf, "max", "vendor", "bundle", "1", "alise", "update", false)

	testEnforceSync(t, enf, "tony", "vendor", "games", "1", "alise", "read", false)
	testEnforceSync(t, enf, "tony", "vendor", "games", "1", "alise", "write", false)
	testEnforceSync(t, enf, "tony", "vendor", "statistic", "1", "alise", "write", false)
	testEnforceSync(t, enf, "tony", "vendor", "price", "1", "alise", "read", false)
	testEnforceSync(t, enf, "tony", "vendor", "games", "42", "alise", "read", true)
	testEnforceSync(t, enf, "tony", "vendor", "games", "42", "alise", "write", true)
	testEnforceSync(t, enf, "tony", "vendor", "statistic", "42", "alise", "write", true)
	testEnforceSync(t, enf, "tony", "vendor", "price", "42", "alise", "read", true)
	testEnforceSync(t, enf, "tony", "vendor", "bundle", "1", "alise", "create", true)
	testEnforceSync(t, enf, "tony", "vendor", "bundle", "1", "alise", "read", true)
	testEnforceSync(t, enf, "tony", "vendor", "bundle", "1", "alise", "update", false)

	testEnforceSync(t, enf, "nick", "*", "games", "1", "alise", "read", true)
	testEnforceSync(t, enf, "nick", "vendor2", "games", "1", "alise", "read", true)

	testEnforceSync(t, enf, "ted", "vendor", "games", "1", "alise", "read", true)
	testEnforceSync(t, enf, "ted", "vendor", "price", "1", "alise", "read", true)
	testEnforceSync(t, enf, "ted", "vendor", "price", "1", "alise", "write", false)

	testEnforceSync(t, enf, "alex", "vendor", "games", "1", "alise", "read", true)
	testEnforceSync(t, enf, "alex", "vendor", "price", "1", "alise", "read", true)
	testEnforceSync(t, enf, "alex", "vendor", "price", "1", "alise", "write", false)
	testEnforceSync(t, enf, "alex", "vendor", "statistic", "1", "alise", "write", true)
	testEnforceSync(t, enf, "alex", "vendor", "statistic", "1", "alise", "write", true)
}

func TestEnforcer_Enforce2(t *testing.T) {
	//shouldBe := require.New(t)
	enf := NewEnforcer()

	enf.AddPolicy(Policy{Role: "admin", Domain: "vendor", ResourceType: "game", ResourceId: "*", Action: "any", Effect: "allow"})
	//enf.AddPolicy(Policy{Role: "admin", Domain: "vendor", ResourceType: "list", ResourceId: "skip", Action: "any", Effect: "allow"})

	enf.AddRole(Role{Role: "admin", User: "superman", Domain: "vendor", Owner: "owner", RestrictedResourceId: nil})

	//shouldBe.True(enf.Enforce(Context{Domain:"vendor", User:"superman", ResourceOwner:"owner", Action:"read", ResourceId: "*", Resource: "game"}))
	//shouldBe.True(enf.Enforce(Context{Domain:"vendor", User:"superman", ResourceOwner:"owner", Action:"read", ResourceId: "*", Resource: "list"}))

	//shouldBe.False(enf.Enforce(Context{Domain:"vendor", User:"superman", ResourceOwner:"another_owner", Action:"read", ResourceId: "*", Resource: "game"}))
	//shouldBe.False(enf.Enforce(Context{Domain:"vendor", User:"superman", ResourceOwner:"another_owner", Action:"read", ResourceId: "*", Resource: "list"}))
}

func TestEnforcer_GetRolesForUser(t *testing.T) {
	Copy("./conf/keymatch_policy.csv", "./conf/copy_keymatch_policy.csv")
	a := fileadapter.NewAdapter("./conf/copy_keymatch_policy.csv")
	enf := NewEnforcer(a)

	testGetRoleForUser(t, enf, []string{"admin", "viewer", "analytic"}, "max", "vendor")
	testGetRoleForUser(t, enf, []string{"viewer", "analytic"}, "ted", "vendor")
	testGetRoleForUser(t, enf, []string{"admin", "viewer", "analytic"}, "tony", "vendor")

	testGetRoleForUser(t, enf, []string{}, "max", "vendor1")
	testGetRoleForUser(t, enf, []string{}, "ted", "vendor1")
	testGetRoleForUser(t, enf, []string{}, "tony", "vendor1")

	testGetRoleForUser(t, enf, []string{"admin2"}, "nick", "vendor1")
	testGetRoleForUser(t, enf, []string{"admin2"}, "nick", "vendor2")
	testGetRoleForUser(t, enf, []string{"admin2"}, "nick", "vendor3")
}

func TestEnforcer_GetUsersForRole(t *testing.T) {
	Copy("./conf/keymatch_policy.csv", "./conf/copy_keymatch_policy.csv")
	a := fileadapter.NewAdapter("./conf/copy_keymatch_policy.csv")
	enf := NewEnforcer(a)

	testGetUsersForRole(t, enf, []string{"nick"}, "admin2", "any domain")
	testGetUsersForRole(t, enf, []string{"nick"}, "admin2", "*")
	testGetUsersForRole(t, enf, []string{"nick"}, "admin2", "")
	testGetUsersForRole(t, enf, []string{"nick"}, "admin2", "", "alise")

	testGetUsersForRole(t, enf, []string{}, "admin", "vendor2")
	testGetUsersForRole(t, enf, []string{}, "admin", "vendor", "frenc")
	testGetUsersForRole(t, enf, []string{}, "admin", "vendor", "alise", "role")
	testGetUsersForRole(t, enf, []string{}, "admin", "vendor", "alise", "admin", "1")
	testGetUsersForRole(t, enf, []string{"max", "tony"}, "admin", "vendor")
	testGetUsersForRole(t, enf, []string{"max", "tony"}, "admin", "vendor", "alise")
	testGetUsersForRole(t, enf, []string{"max", "tony"}, "admin", "vendor", "alise", "admin")

	testGetUsersForRole(t, enf, []string{"max"}, "admin", "vendor", "alise", "admin", "*")
	testGetUsersForRole(t, enf, []string{"tony"}, "admin", "vendor", "alise", "admin", "42")

	testGetUsersForRole(t, enf, []string{"max", "tony"}, "admin", "vendor", &Restriction{Owner: "alise"})
	testGetUsersForRole(t, enf, []string{"max", "tony"}, "admin", "vendor", &Restriction{Owner: "alise", Role: "admin"})
	testGetUsersForRole(t, enf, []string{"max"}, "admin", "vendor", &Restriction{Owner: "alise", Role: "admin", UUID: "*"})
	testGetUsersForRole(t, enf, []string{"tony"}, "admin", "vendor", &Restriction{Owner: "alise", Role: "admin", UUID: "42"})

	assert.Panics(t, func() {
		testGetUsersForRole(t, enf, []string{}, "admin", "", nil)
	})

}

func TestEnforcer_GetPermissionsForUser(t *testing.T) {
	Copy("./conf/keymatch_policy.csv", "./conf/copy_keymatch_policy.csv")
	a := fileadapter.NewAdapter("./conf/copy_keymatch_policy.csv")
	enf := NewEnforcer(a)

	p := enf.GetPermissionsForUser("max", "vendor")

	assert.Equal(t, "max", p.User)
	assert.Equal(t, "vendor", p.Domain)

	assert.Len(t, p.Permissions, 4)

	assert.Equal(t, "admin", p.Permissions[0].Role)
	assert.Equal(t, "vendor", p.Permissions[0].Domain)
	assert.Equal(t, "games", p.Permissions[0].Resource)
	assert.Equal(t, "*", p.Permissions[0].UUID)
	assert.Equal(t, "any", p.Permissions[0].Action)
	assert.Equal(t, true, p.Permissions[0].Allowed)
	assert.Len(t, p.Permissions[0].Restrictions, 1)
	assert.Equal(t, "alise", p.Permissions[0].Restrictions[0].Owner)
	assert.Equal(t, "admin", p.Permissions[0].Restrictions[0].Role)
	assert.Equal(t, "*", p.Permissions[0].Restrictions[0].UUID)

	assert.Equal(t, "admin", p.Permissions[1].Role)
	assert.Equal(t, "vendor", p.Permissions[1].Domain)
	assert.Equal(t, "bundle", p.Permissions[1].Resource)
	assert.Equal(t, "skip", p.Permissions[1].UUID)
	assert.Equal(t, "(create)|(read)", p.Permissions[1].Action)
	assert.Equal(t, true, p.Permissions[1].Allowed)
	assert.Len(t, p.Permissions[1].Restrictions, 1)
	assert.Equal(t, "alise", p.Permissions[1].Restrictions[0].Owner)
	assert.Equal(t, "admin", p.Permissions[1].Restrictions[0].Role)
	assert.Equal(t, "*", p.Permissions[1].Restrictions[0].UUID)

	assert.Len(t, p.UnmatchedRestrictions, 1)
	assert.Equal(t, "unknown", p.UnmatchedRestrictions[0].Owner)
	assert.Equal(t, "random", p.UnmatchedRestrictions[0].Role)
	assert.Equal(t, "*", p.UnmatchedRestrictions[0].UUID)
}

func TestEnforcer_GetPermissionsForUser_Filtered(t *testing.T) {
	shouldBe := require.New(t)

	enf := NewEnforcer()

	enf.AddPolicy(Policy{"admin", "vendor", "game", "*", "any", "allow"})
	role := Role{"stan", "admin", "vendor", "alise", []string{"50"}}
	role2 := Role{"stan", "admin", "vendor", "david", []string{"51"}}
	role3 := Role{"stan", "admin", "vendor", "greg", nil}
	enf.AddRole(role)
	enf.AddRole(role2)
	enf.AddRole(role3)

	userPermissions := enf.GetPermissionsForUser("stan", "vendor", "alise")
	shouldBe.NotNil(userPermissions)
	shouldBe.Equal("stan", userPermissions.User)
	shouldBe.Equal("vendor", userPermissions.Domain)
	shouldBe.Equal(0, len(userPermissions.UnmatchedRestrictions))
	shouldBe.Equal(1, len(userPermissions.Permissions))
	shouldBe.Equal("vendor", userPermissions.Permissions[0].Domain)
	shouldBe.Equal("any", userPermissions.Permissions[0].Action)
	shouldBe.Equal("game", userPermissions.Permissions[0].Resource)
	shouldBe.Equal("admin", userPermissions.Permissions[0].Role)
}

func TestEnforcer_GetPermissionsForUserWithPermissions(t *testing.T) {
	Copy("./conf/restrict_policy.csv", "./conf/copy_restrict_policy.csv")
	a := fileadapter.NewAdapter("./conf/copy_restrict_policy.csv")
	enf := NewEnforcer(a)

	p := enf.GetPermissionsForUser("max", "vendor")
	assert.Equal(t, "alise", p.Permissions[0].Restrictions[0].GetRaw())
	assert.Equal(t, "alise", p.Permissions[0].Restrictions[0].Owner)
	assert.Equal(t, "", p.Permissions[0].Restrictions[0].Role)
	assert.Equal(t, "", p.Permissions[0].Restrictions[0].UUID)

	p = enf.GetPermissionsForUser("tony", "vendor")
	assert.Equal(t, "alise/viewer", p.Permissions[0].Restrictions[0].GetRaw())
	assert.Equal(t, "alise", p.Permissions[0].Restrictions[0].Owner)
	assert.Equal(t, "viewer", p.Permissions[0].Restrictions[0].Role)
	assert.Equal(t, "", p.Permissions[0].Restrictions[0].UUID)

	p = enf.GetPermissionsForUser("fred", "vendor")
	assert.Equal(t, "alise/analytic/*", p.Permissions[0].Restrictions[0].GetRaw())
	assert.Equal(t, "alise", p.Permissions[0].Restrictions[0].Owner)
	assert.Equal(t, "analytic", p.Permissions[0].Restrictions[0].Role)
	assert.Equal(t, "*", p.Permissions[0].Restrictions[0].UUID)

	assert.Panics(t, func() {
		enf.GetPermissionsForUser("panic", "vendor")
	})
}

func TestEnforcer_RemoveResourceRestrictionForUser(t *testing.T) {
	Copy("./conf/restrict_policy.csv", "./conf/copy_restrict_policy.csv")
	a := fileadapter.NewAdapter("./conf/copy_restrict_policy.csv")
	enf := NewEnforcer(a)

	for _, r := range enf.GetUserRestrictions("fred") {
		enf.RemoveRestrictionFromUser("fred", r)
	}

	enf.AddRestrictionToUser("fred", &Restriction{"alise", "analytic", "5"})

	testEnforceSync(t, enf, "fred", "vendor", "statistic", "1", "alise", "read", false)
	testEnforceSync(t, enf, "fred", "vendor", "statistic", "5", "alise", "read", true)
}

func TestNewEnforcer(t *testing.T) {
	assert.NotPanics(t, func() {
		assert.IsType(t, &Enforcer{}, NewEnforcer())
	})

	assert.NotPanics(t, func() {
		assert.IsType(t, &Enforcer{}, NewEnforcer(casbin.NewSyncedEnforcer()))
	})

	Copy("./conf/keymatch_policy.csv", "./conf/copy_keymatch_policy.csv")
	a := fileadapter.NewAdapter("./conf/copy_keymatch_policy.csv")
	w := &rediswatcher.Watcher{}

	assert.NotPanics(t, func() {
		assert.IsType(t, &Enforcer{}, NewEnforcer(a, w))
	})
}

func TestNewEnforcerWithWrongArguments(t *testing.T) {
	Copy("./conf/keymatch_policy.csv", "./conf/copy_keymatch_policy.csv")
	a := fileadapter.NewAdapter("./conf/copy_keymatch_policy.csv")
	w := &rediswatcher.Watcher{}

	set := [][]interface{}{
		{"string"},
		{w, a},
		{a, "string"},
		{1, 2, 3},
	}

	for _, val := range set {
		assert.Panics(t, func() {
			assert.IsType(t, &Enforcer{}, NewEnforcer(val...))
		})
	}
}

func TestEnforcer_Save(t *testing.T) {
	enf := NewEnforcer()
	assert.Nil(t, enf.Save())
}

func testEnforceSync(t *testing.T, e *Enforcer, user, domain, obj, uuid, owner, action string, res bool) {
	t.Helper()

	req := Context{
		user,
		domain,
		obj,
		uuid,
		owner,
		action,
	}

	if e.Enforce(req) != res {
		t.Errorf("%v : %t, supposed to be %t", req, !res, res)
	}
}

func testGetRoleForUser(t *testing.T, e *Enforcer, roles []string, user, domain string) {
	t.Helper()
	assert.ElementsMatch(t, roles, e.GetRolesForUser(user, domain))
}

func testGetUsersForRole(t *testing.T, e *Enforcer, users []string, role, domain string, filters ...interface{}) {
	t.Helper()

	usersMatch := e.GetUsersForRole(role, domain, filters...)
	assert.ElementsMatch(t, users, usersMatch)
}

// Copy the src file to dst. Any existing file will be overwritten and will not
// copy file attributes.
func Copy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}