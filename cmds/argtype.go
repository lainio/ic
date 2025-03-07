package cmds

import "errors"

type ArgType string

const (
	DBType       ArgType = "db"
	DigestType   ArgType = "digest"
	DigestV2Type ArgType = "digestv2"
	IDKType      ArgType = "idk"
	AliasType    ArgType = "alias"

	NameList = "(db|digest|digestv2|idk|alias)"
)

// Validate the flag value
func (t *ArgType) String() string {
	return string(*t)
}

func (t *ArgType) Set(value string) error {
	switch value {
	case string(DBType), string(DigestType), string(DigestV2Type),
		string(IDKType), string(AliasType):
		*t = ArgType(value)
		return nil
	default:
		return errors.New("must be one of" + NameList)
	}
}

func (t *ArgType) Type() string {
	return "ArgType"
}
