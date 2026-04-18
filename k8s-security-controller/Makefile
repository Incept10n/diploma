.PHONY: install uninstall upgrade list deps repos

repos:
	helm repo add falcosecurity https://falcosecurity.github.io/charts || true
	helm repo add sysdig https://charts.sysdig.com || true
	helm repo update

deps: repos
	helm dependency update

#install: deps
install:
	helm install k8s-security-controller . --namespace si --create-namespace

upgrade: deps
	helm upgrade k8s-security-controller -n si .

uninstall:
	helm uninstall k8s-security-controller -n si

list:
	helm list --all-namespaces
