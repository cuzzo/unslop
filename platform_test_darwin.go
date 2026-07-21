//go:build darwin

package main

import "syscall"

func makeMockStat(atimeSec, ctimeSec int64) interface{} {
	return &syscall.Stat_t{
		Atimespec: syscall.Timespec{Sec: atimeSec, Nsec: 0},
		Ctimespec: syscall.Timespec{Sec: ctimeSec, Nsec: 0},
	}
}
