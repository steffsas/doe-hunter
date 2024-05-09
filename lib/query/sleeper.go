package query

import "time"

type sleeper interface {
	Sleep(d time.Duration)
}

type defaultSleeper struct{}

func (d defaultSleeper) Sleep(duration time.Duration) {
	time.Sleep(duration)
}

func newDefaultSleeper() *defaultSleeper {
	return &defaultSleeper{}
}
