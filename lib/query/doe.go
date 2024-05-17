package query

type DoEQuery struct {
	DNSQuery
}

type DoEResponse struct {
	DNSResponse

	CertificateVerified bool `json:"certificate_verified"`
	CertificateValid    bool `json:"certificate_valid"`
}
