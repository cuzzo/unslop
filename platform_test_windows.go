//go:build windows

package main

func makeMockStat(atimeSec, ctimeSec int64) interface{} {
	return nil
}
