// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"unsafe"
)

func openTarget() (*os.File, int64, error) {
	fd, err := unix.Open(devicePath, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, err
	}
	file := os.NewFile(uintptr(fd), devicePath)
	fail := func(err error) (*os.File, int64, error) { file.Close(); return nil, 0, err }
	info, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	if info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice != 0 {
		return fail(fmt.Errorf("target must be an attached block device"))
	}
	var size uint64
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.BLKGETSIZE64, uintptr(unsafe.Pointer(&size)))
	if errno != 0 {
		return fail(errno)
	}
	if size > uint64(maxDiskBytes) {
		return fail(fmt.Errorf("target too large"))
	}
	return file, int64(size), nil
}
