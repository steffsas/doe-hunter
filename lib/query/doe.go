package query

type DoEQuery struct {
	DNSQuery
}

type DoEResponse struct {
	DNSResponse

	CertificateValid bool `json:"certificate_valid"`
}
