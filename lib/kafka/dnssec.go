package kafka

type KafkaDNSSECScan struct {
	BasicKafkaScan

	Target string `json:"target"`
}

func (scan *KafkaDNSSECScan) GetTarget() string {
	return scan.Target
}

func NewKafkaDNSSECScan(runId, rootScanId, parentScanId, host, target string, onBlockList bool) *KafkaDNSSECScan {
	return &KafkaDNSSECScan{
		BasicKafkaScan: *NewBasicKafkaScan(runId, rootScanId, parentScanId, host, onBlockList),
		Target:         target,
	}
}
