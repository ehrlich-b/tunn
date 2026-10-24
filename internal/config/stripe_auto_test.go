package config

import (
	"reflect"
	"testing"
)

func TestAutoActivationPriceAllowlistConfig(t *testing.T) {
	t.Setenv("TUNN_STRIPE_PRO_PRICE_IDS", " price_monthly , price_yearly, ")
	for _, env := range []string{"dev", "prod"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("TUNN_ENV", env)
			cfg, err := LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cfg.StripeProPriceIDs, []string{"price_monthly", "price_yearly"}) {
				t.Fatal(cfg.StripeProPriceIDs)
			}
		})
	}
}
