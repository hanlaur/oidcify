.PHONY: build
build:
	GOOS=linux go build ./...

.PHONY: debugbuild
debugbuild:
	go build -gcflags="all=-N -l"  ./...
	
.PHONY: format
format:
	gofumpt -w .

.PHONY: lint
lint:
	golangci-lint run --config .golangci.yaml

.PHONY: test
test:
	go test -v -coverprofile cover.out
	go tool cover -html cover.out -o cover.html
	

.PHONY: install-tooling
install-tooling:
	# Warning: Tools are installed without pinning to specific commit or version. 
	# There is no guarantee that the install sources would provide same result as it did during development.
	# Install at own risk.
	@if [ "$(ACCEPT_RISK)" != "yes" ]; then echo Tooling will be installed from Internet. Use at own risk. Verify tooling sources referenced in Makefile, set the required environment var and try again; exit 1; fi
	go install mvdan.cc/gofumpt@latest
	go install github.com/goreleaser/goreleaser/v2@latest
	go install github.com/google/go-licenses@latest
	go install github.com/vektra/mockery/v2@latest
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin

.PHONY: release-test
release-test:
	goreleaser release --clean --snapshot

.PHONY: setup-labels
setup-labels:
	gh label create breaking --description "Breaking changes" --color FF0000
	gh label create feature --description "New features" --color 1D76DB
	gh label create fix --description "Bug fixes" --color 0E8A16
	gh label create chore --description "Maintenance tasks" --color F9D0C4

.PHONY: clean
clean:
	rm -rf cover.out cover.html
	rm -rf dist oidcify mocks
	rm -rf component_licenses

.PHONY: update-mocks
update-mocks:
	mockery
	mv mocks/github.com/hanlaur/oidcify/mock_Kong.go mock_Kong.go

.PHONY: license-report
license-report:
	go-licenses save ./... --save_path=component_licenses --force

.PHONY: docker
docker: build license-report
	docker build . -t kong-with-oidcify

