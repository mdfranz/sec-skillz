# Makefile for Agno Docker image

# Get the short git hash
GIT_HASH := $(shell git rev-parse --short HEAD)
IMAGE_NAME := agno-skillrunner

# Set default target
.DEFAULT_GOAL := build

.PHONY: build run

build:
	docker build -t $(IMAGE_NAME):$(GIT_HASH) .
	docker tag $(IMAGE_NAME):$(GIT_HASH) $(IMAGE_NAME):latest
	@echo "Built $(IMAGE_NAME):$(GIT_HASH) and tagged as latest"

run:
	docker run --rm -it \
		-v $(PWD)/data:/app/data \
		-v $(PWD)/skills:/app/skills \
		-e GOOGLE_API_KEY=$(GOOGLE_API_KEY) \
		-e ANTHROPIC_API_KEY=$(ANTHROPIC_API_KEY) \
		-e OPENAI_API_KEY=$(OPENAI_API_KEY) \
		$(IMAGE_NAME):latest $(CMD)
