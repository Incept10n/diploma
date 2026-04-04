.PHONY: deploy uninstall upgrade list

install:
	helm install k8s-security-controller . --namespace si --create-namespace

uninstall:
	helm uninstall k8s-security-controller -n si

upgrade: 
	helm upgrade k8s-security-controller -n si .

list:
	helm list --all-namespaces
