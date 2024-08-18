package kafka

type DoEKafkaScan struct {
	BasicKafkaScan

	SkipCertificateVerify bool `json:"skip_certificate_verify"`
}

func NewDoEKafkaScan(runId, rootScanId, parentScanId, host string, onBlockList, skipCertificateVerify bool) *DoEKafkaScan {
	return &DoEKafkaScan{
		BasicKafkaScan:        *NewBasicKafkaScan(runId, rootScanId, parentScanId, host, onBlockList),
		SkipCertificateVerify: skipCertificateVerify,
	}
}
