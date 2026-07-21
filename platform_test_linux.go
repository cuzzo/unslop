//go:build linux

package main

import "syscall"

func makeMockStat(atimeSec, ctimeSec int64) interface{} {
	return &syscall.Stat_t{
		Atim: syscall.Timespec{Sec: atimeSec, Nsec: 0},
		Ctim: syscall.Timespec{Sec: ctimeSec, Nsec: 0},
	}
}
