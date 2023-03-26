package bpf

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	possibleCPUSysfsPath = "/sys/devices/system/cpu/possible"
)

func GetNumPossibleCPUs() (int, error) {
	data, err := os.ReadFile(possibleCPUSysfsPath)
	if err != nil {
		return 0, errors.Join(err, fmt.Errorf("unable to open %q", possibleCPUSysfsPath))
	}

	var start, end int
	count := 0
	for _, s := range strings.Split(string(data), ",") {
		// Go's scanf will return an error if a format cannot be fully matched.
		// So, just ignore it, as a partial match (e.g. when there is only one
		// CPU) is expected.
		n, err := fmt.Sscanf(s, "%d-%d", &start, &end)
		switch n {
		case 0:
			return 0, errors.Join(err, fmt.Errorf("failed to scan %q to retrieve number of possible CPUs", s))
		case 1:
			count++
		default:
			count += (end - start + 1)
		}
	}
	return count, nil
}
