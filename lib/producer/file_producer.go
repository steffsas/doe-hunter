package producer

import (
	"bufio"
	"os"

	"github.com/google/uuid"
)

type FileProducer struct {
	GetProduceableScans GetProduceableScans
	Producer            ScanProducer
}

func (dp *FileProducer) Produce(file string) error {
	// open file and read line by line to create scans
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	runId := uuid.New().String()

	// watch for events
	dp.Producer.WatchEvents()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if len(line) > 0 {
			scans := dp.GetProduceableScans(line, runId)
			for _, s := range scans {
				err = dp.Producer.Produce(s.Scan, s.Topic)
				if err != nil {
					return err
				}
			}
		}
	}

	dp.Producer.Flush(0)
	dp.Producer.Close()

	return nil
}

func NewFileProducer(newScans GetProduceableScans, producer ScanProducer) *FileProducer {
	return &FileProducer{
		GetProduceableScans: newScans,
		Producer:            producer,
	}
}
