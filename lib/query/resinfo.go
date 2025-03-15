package query

// RESINFO record type is currently not supported by miekg/dns
const TypeRESINFO = uint16(261)

func NewResInfoQuery(targetName string) *ConventionalDNSQuery {
	q := NewConventionalQuery()

	q.QueryMsg.SetQuestion(targetName, TypeRESINFO)

	return q
}

func NewResInfoQueryHandler(config *QueryConfig) *ConventionalDNSQueryHandler {
	return NewConventionalDNSQueryHandler(config)
}
