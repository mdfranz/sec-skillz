#!/bin/bash
# Wrapper script to run the Agno Skill Runner Docker container

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running."
    exit 1
fi

# Define image name
IMAGE_NAME="agno-skillrunner:latest"

# Get the directory of the script to resolve relative paths if needed
# Assuming the script is run from the project root or similar context where data/ and skills/ exist
# If you want to make it robust to where it's called from, you might need to adjust these paths
DATA_DIR="$(pwd)/data"
SKILLS_DIR="$(pwd)/skills"

# Check if data and skills directories exist
if [ ! -d "$DATA_DIR" ]; then
    echo "Warning: '$DATA_DIR' does not exist. Creating it..."
    mkdir -p "$DATA_DIR"
fi

if [ ! -d "$SKILLS_DIR" ]; then
    echo "Warning: '$SKILLS_DIR' does not exist. Please ensure you are running this from the project root."
fi

# Check for .env file
if [ -f ".env" ]; then
    ENV_FILE_ARGS="--env-file .env"
    echo "Using environment variables from .env file."
else
    ENV_FILE_ARGS=""
    echo "No .env file found. Using current shell environment variables."
fi

# Build environment variable arguments
ENV_VARS=""
if [ -n "$GOOGLE_API_KEY" ]; then ENV_VARS="$ENV_VARS -e GOOGLE_API_KEY=$GOOGLE_API_KEY"; fi
if [ -n "$ANTHROPIC_API_KEY" ]; then ENV_VARS="$ENV_VARS -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY"; fi
if [ -n "$OPENAI_API_KEY" ]; then ENV_VARS="$ENV_VARS -e OPENAI_API_KEY=$OPENAI_API_KEY"; fi

# Run the Docker container
# Passes all arguments provided to the script ($@) to the entrypoint
docker run --rm -it \
    -v "$DATA_DIR":/app/data \
    -v "$SKILLS_DIR":/app/skills \
    $ENV_FILE_ARGS \
    $ENV_VARS \
    "$IMAGE_NAME" "$@"
