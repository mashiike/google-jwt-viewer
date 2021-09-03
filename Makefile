export TAG := $(shell git log -1 --format=%h)
export AWS_ACCOUNT_ID := $(shell aws sts get-caller-identity --query 'Account' --output text)
export ECR=$(AWS_ACCOUNT_ID).dkr.ecr.ap-northeast-1.amazonaws.com


.PHONY: build
build:
	docker build -t google-jwt-viewer:$(TAG) -t $(ECR)/google-jwt-viewer:$(TAG) -t $(ECR)/google-jwt-viewer:latest -f docker/Dockerfile .

.PHONY: ecr-login
ecr-login:
	aws ecr get-login-password --region ap-northeast-1 | docker login --username AWS --password-stdin $(ECR)

.PHONY: push
push:
	docker push $(ECR)/google-jwt-viewer:$(TAG)
	docker push $(ECR)/google-jwt-viewer:latest
