.PHONY: build test docker-build clean docker-rebuild

build:
	go build -o bin/k8s-security-controller .

docker-build:
	docker build -t incept1on999/k8s-security-controller:latest . --no-cache

docker-push:
	docker push incept1on999/k8s-security-controller:latest

docker-rebuild:
	$(MAKE) docker-build
	$(MAKE) docker-push

clean:
	rm -rf bin/

install-deps:
	go mod tidy

run:
	go run *.go

run-dev:
	go run *.go -kubeconfig ~/.kube/config
