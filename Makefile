GO ?= go
GOBIN ?= $$($(GO) env GOPATH)/
GOLANGCI_LINT ?= $(GOBIN)/golangci-lint
GOLANGCI_LINT_VERSION ?= v1.58.1

.PHONY: install-go-test-coverage
install-go-test-coverage:
	go install github.com/vladopajic/go-test-coverage/v2@latest

.PHONY: get-golangcilint
get-golangcilint:
	test -f $(GOLANGCI_LINT) || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$($(GO) env GOPATH)/bin $(GOLANGCI_LINT_VERSION)


.PHONY: test
test:
	go test ./lib/... 

.PHONY: test-coverage
test-coverage: test
	go test ./lib/... -coverprofile=./profile.cov -cover
	${GOBIN}/go-test-coverage --config=./.testcoverage.yml

.PHONY: lint
lint:
	$(GOLANGCI_LINT) run -- $(shell go work edit -json | jq -c -r '[.Use[].DiskPath] | map_values(. + "/...")[]')