# Makefile for Agno Docker image

# Get the short git hash
GIT_HASH := $(shell git rev-parse --short HEAD)
IMAGE_NAME := agno-skillrunner

# Check for .env file
ifneq (,$(wildcard .env))
    ENV_FILE_ARG := --env-file .env
else
    ENV_FILE_ARG :=
endif

# Set default target
.DEFAULT_GOAL := build

.PHONY: build run install

build:
	docker build -t $(IMAGE_NAME):$(GIT_HASH) .
	docker tag $(IMAGE_NAME):$(GIT_HASH) $(IMAGE_NAME):latest
	@echo "Built $(IMAGE_NAME):$(GIT_HASH) and tagged as latest"

install:
	mkdir -p ~/bin
	cp agno-runner.sh ~/bin/agno-runner
	chmod +x ~/bin/agno-runner
	cp run_os_local.sh ~/bin/agno-os-local
	chmod +x ~/bin/agno-os-local
	@echo "Installed agno-runner and agno-os-local to ~/bin"

# Conditional variable passing
# Only pass -e flags if the variables are set to avoid overriding .env values with empty strings
RUN_ARGS :=
ifneq ($(GOOGLE_API_KEY),)
    RUN_ARGS += -e GOOGLE_API_KEY=$(GOOGLE_API_KEY)
endif
ifneq ($(ANTHROPIC_API_KEY),)
    RUN_ARGS += -e ANTHROPIC_API_KEY=$(ANTHROPIC_API_KEY)
endif
ifneq ($(OPENAI_API_KEY),)
    RUN_ARGS += -e OPENAI_API_KEY=$(OPENAI_API_KEY)
endif

run:
	docker run --rm -it \
		-v $(PWD)/data:/app/data \
		-v $(PWD)/skills:/app/skills \
		$(ENV_FILE_ARG) \
		$(RUN_ARGS) \
		$(IMAGE_NAME):latest $(CMD)

os:
	docker run --rm -it \
		-p 8000:8000 \
		-v $(PWD)/data:/app/data \
		-v $(PWD)/skills:/app/skills \
		$(ENV_FILE_ARG) \
		$(RUN_ARGS) \
		--entrypoint uvicorn \
		$(IMAGE_NAME):latest agent_os:app --host 0.0.0.0 --port 8000
