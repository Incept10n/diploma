.PHONY: docker-build docker-push redeploy

docker-build:
	docker build -t incept1on999/k8s-security-controller:cron . --no-cache

docker-push:
	docker push incept1on999/k8s-security-controller:cron

redeploy:
	$(MAKE) docker-build
	$(MAKE) docker-push
	kubectl apply -f deployment.yaml
	kubectl rollout restart deployment random-logger-cron