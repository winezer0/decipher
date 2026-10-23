package cracker

import (
	"flag"
	"testing"
)

var measurePreparedMemory = flag.Bool("prepared-memory", false, "measure prepared cracking peak working set in fresh Windows processes")

func TestPreparedPeakWorkingSet(t *testing.T) {
	if !*measurePreparedMemory {
		t.Skip("run explicitly with -prepared-memory")
	}
	testWorkerPeakWorkingSet(t, preparedWorkloads)
}
