//go:build !linux

// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"os"
)

func openTarget() (*os.File, int64, error) {
	return nil, 0, fmt.Errorf("block importer requires Linux")
}
