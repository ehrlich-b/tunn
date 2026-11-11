package common

import "context"

type funnelSourceKey struct{}

// NormalizeFunnelSource retains only a small, fixed channel vocabulary.
func NormalizeFunnelSource(source string) string {
	switch source {
	case "":
		return "direct"
	case "alt", "saashub", "docs", "thread", "direct", "other":
		return source
	default:
		return "other"
	}
}

// WithFunnelSource carries only the normalized first-touch channel to signup.
func WithFunnelSource(ctx context.Context, source string) context.Context {
	return context.WithValue(ctx, funnelSourceKey{}, NormalizeFunnelSource(source))
}

func FunnelSource(ctx context.Context) string {
	source, _ := ctx.Value(funnelSourceKey{}).(string)
	return NormalizeFunnelSource(source)
}
