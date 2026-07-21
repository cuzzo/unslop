//go:build windows

package platform

func makeMockStat(atimeSec, ctimeSec int64) interface{} {
	return nil
}
