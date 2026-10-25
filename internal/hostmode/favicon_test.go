package hostmode

import (
	"gopkg.in/yaml.v3"
	"testing"
)

func TestFaviconConfig(t *testing.T) {
	for _, input := range []string{"name: api\n", "name: api\nno_favicon: true\n"} {
		var tunnel Tunnel
		if err := yaml.Unmarshal([]byte(input), &tunnel); err != nil {
			t.Fatal(err)
		}
		if tunnel.NoFavicon != (len(input) > 10) {
			t.Fatal(tunnel.NoFavicon)
		}
	}
}
