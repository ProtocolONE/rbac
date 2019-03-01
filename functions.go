package rbac

import (
	"github.com/casbin/casbin/util"
	"strings"
)

type EnforceFunction func(args ...interface{}) (interface{}, error)

func BothSideMatchKeysFunc(args ...interface{}) (interface{}, error) {
	name1 := args[0].(string)
	name2 := args[1].(string)

	return bool(BothSideMatchKeys(name1, name2)), nil
}

func BothSideMatchKeys(name1, name2 string) bool {
	return MatchKeys(name1, name2) || MatchKeys(name2, name1)
}

// MatchKeysFunc is wrapper for MatchKeys
func MatchKeysFunc(args ...interface{}) (interface{}, error) {
	name1 := args[0].(string)
	name2 := args[1].(string)

	return bool(MatchKeys(name1, name2)), nil
}

// MatchKeys determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*"
func MatchKeys(name1, name2 string) bool {
	name2 = strings.Replace(name2, "*", ".*", -1)
	return util.RegexMatch(name1, "^"+name2+"$")
}
