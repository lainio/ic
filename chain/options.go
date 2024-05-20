package chain

type Opts func(*Options)

type Options struct {
	Position     int
	Rotation     bool
	AllowRouting bool
	Resolver     bool
	Endpoint     string

	// TODO: future ones, endpoint or does this belong to key.Info? It might be
	// good if we could share same key with the Tor service and our ID?
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
