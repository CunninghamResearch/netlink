set default-list := true
set minimum-version := "1.55.0"


##############################################################################
# Source control.
##############################################################################

[group("source")]
[doc("tag a release version with message")]
tag version message:
	git tag -a {{version}} -m "{{message}}"



##############################################################################
# Testing.
##############################################################################

[group("test")]
[doc("run full golanci-lint test suite")]
lint:
	golangci-lint run


[group("test")]
[doc("run all non-integration tests")]
test:
	go test -v -trimpath ./...


[group("test")]
[doc("run all tests")]
test-all:
	go test -v -trimpath -tags integration ./...
