package cracker

import (
	"flag"
	"testing"
)

var measureSHAWorkerMemory = flag.Bool("sha-worker-memory", false, "measure SHA worker peak working set in fresh Windows processes")

func TestSHAWorkerPeakWorkingSet(t *testing.T) {
	if !*measureSHAWorkerMemory {
		t.Skip("run explicitly with -sha-worker-memory")
	}
	testWorkerPeakWorkingSet(t, shaWorkerWorkloads)
}
