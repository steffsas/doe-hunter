package svcb_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseDDRSVCB(t *testing.T) {
	// test cases

	c := new(dns.Client)
	c.Net = "tcp"
	c.Timeout = time.Duration(5) * time.Second

	query := new(dns.Msg)
	query.SetQuestion("_dns.resolver.arpa.", dns.TypeSVCB)

	answer, _, err := c.Exchange(query, "94.140.14.140:53")

	if err != nil {
		t.Errorf("Error in query: %v", err)
		return
	}

	if answer == nil {
		t.Errorf("No answer received")
		return
	}

	for _, answer := range answer.Answer {
		svcRecord, ok := answer.(*dns.SVCB)
		if !ok {
			t.Errorf("could not cast DDR DNS answer to SVCB")
			continue
		}

		for _, val := range svcRecord.Value {
			fmt.Println(val.Key().String())
		}
	}
}
