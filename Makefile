GOBIN ?= $$(go env GOPATH)/bin

.PHONY: install-go-test-coverage
install-go-test-coverage:
	go install github.com/vladopajic/go-test-coverage/v2@latest

.PHONY: check-coverage
check-coverage: install-go-test-coverage
	go test ./lib/... -coverprofile=./profile.cov -cover
	${GOBIN}/go-test-coverage --config=./.testcoverage.yml