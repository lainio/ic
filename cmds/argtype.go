package cmds

import "errors"

type ArgType string

const (
	DBType     ArgType = "db"
	DigestType ArgType = "digest"
	IDKType    ArgType = "idk"
	AliasType  ArgType = "alias"
)

// Validate the flag value
func (t *ArgType) String() string {
	return string(*t)
}

func (t *ArgType) Set(value string) error {
	switch value {
	case string(DBType), string(DigestType),
		string(IDKType), string(AliasType):
		*t = ArgType(value)
		return nil
	default:
		return errors.New("must be one of [db, digest, idk, alias]")
	}
}

func (t *ArgType) Type() string {
	return "ArgType"
}
