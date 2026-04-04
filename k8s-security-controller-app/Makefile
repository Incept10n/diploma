.PHONY: build test docker-build clean

build:
	go build -o bin/k8s-security-controller .

test:
	go test -v ./...

docker-build:
	docker build -t k8s-security-controller:latest .

docker-push:
	docker push incept1on999/k8s-security-controller:tagname

clean:
	rm -rf bin/

install-deps:
	go mod tidy

run:
	go run *.go

run-dev:
	go run *.go -kubeconfig ~/.kube/config
