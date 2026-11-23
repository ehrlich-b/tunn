package client

import (
	"math/rand/v2"
	"time"
)

// Leave five seconds of the recovery budget for dialing and registration.
const defaultMaxReconnectDelay = 10 * time.Second

// ReconnectDelay uses equal jitter, bounded by half the exponential cap and
// the cap itself. Saturation avoids overflow even after days offline.
func ReconnectDelay(initial, maximum time.Duration, attempt int) time.Duration {
	return reconnectDelay(initial, maximum, attempt, rand.Float64())
}

func reconnectDelay(initial, maximum time.Duration, attempt int, sample float64) time.Duration {
	if initial <= 0 {
		initial = time.Second
	}
	if maximum <= 0 {
		maximum = defaultMaxReconnectDelay
	}
	cap := min(initial, maximum)
	for i := 0; i < attempt && cap < maximum; i++ {
		if cap > maximum/2 {
			cap = maximum
		} else {
			cap *= 2
		}
	}
	sample = max(0, min(1, sample))
	half := cap / 2
	return half + time.Duration(float64(cap-half)*sample)
}
