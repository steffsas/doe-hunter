package kafka

type CanaryKafkaScan struct {
	BasicKafkaScan

	CanaryDomain string `json:"canary_domain"`
}

func NewCanaryKafkaScan(runId, rootScanId, parentScanId, host, canaryDomain string, onBlockList bool) *CanaryKafkaScan {
	return &CanaryKafkaScan{
		BasicKafkaScan: *NewBasicKafkaScan(runId, rootScanId, parentScanId, host, onBlockList),
		CanaryDomain:   canaryDomain,
	}
}
