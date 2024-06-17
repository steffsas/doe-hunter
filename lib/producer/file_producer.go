package producer

import (
	"bufio"
	"os"

	"github.com/google/uuid"
)

type FileProducer struct {
	NewScan  NewScan
	Producer EventProducer
}

func (dp *FileProducer) Produce(file string, topic, vantagePoint string) error {
	// open file and read line by line to create scans
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	runId := uuid.New().String()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if len(line) > 0 {
			s := dp.NewScan(line, runId, vantagePoint)

			// marshall scan
			b, err := s.Marshall()
			if err != nil {
				return err
			}

			err = dp.Producer.Produce(b, topic)
			if err != nil {
				return err
			}
		}
	}

	dp.Producer.Close()

	return nil
}

func NewFileProducer(newScan NewScan, producer EventProducer) *FileProducer {
	return &FileProducer{
		NewScan:  newScan,
		Producer: producer,
	}
}
