package cliopts

import "testing"

func TestFaviconFlag(t *testing.T) {
	for _, args := range [][]string{{"3000"}, {"3000", "--no-favicon"}, {"--no-favicon=false", "3000"}} {
		o, err := ParseServe(args, true)
		if err != nil {
			t.Fatal(err)
		}
		if o.NoFavicon != (len(args) > 1 && args[1] == "--no-favicon") {
			t.Fatalf("%v: %v", args, o.NoFavicon)
		}
	}
}
