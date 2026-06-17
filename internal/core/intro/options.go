package intro

type Opts func(*Options)

type Options struct {
	Position       int
	BackupKeyIndex int
	Rotation       bool
	AllowRouting   bool
	Resolver       bool
	Endpoint       string
}

func NewOptions(options ...Opts) *Options {
	opts := new(Options)
	for _, o := range options {
		o(opts)
	}
	return opts
}

func WithPosition(p int) Opts {
	return func(o *Options) {
		o.Position = p
	}
}

func WithBackupKeyIndex(i int) Opts {
	return func(o *Options) {
		o.BackupKeyIndex = i
	}
}

func WithRotation() Opts {
	return func(o *Options) {
		o.Rotation = true
	}
}

func WithAllowRouting(allow bool) Opts {
	return func(o *Options) {
		o.AllowRouting = allow
	}
}

func WithEndpoint(endpoint string, isResolver bool) Opts {
	return func(o *Options) {
		o.Endpoint = endpoint
		o.Resolver = isResolver
	}
}
