# secode-demo

## Configuration of SeCode Pipeline Demo
This repository contains a demonstration of the SeCode Pipeline, which integrates static code analysis and automated code repair using LLMs. The pipeline is designed to identify and fix vulnerabilities in C++ and Python codebases. Set the following environment variables in your GitHub repository settings to configure the pipeline:

### Secrets
- `OPENAI_KEY`: Your OpenAI API key for accessing LLM services
- `WRITE_TOKEN`: A GitHub token (PAT) for writing results back to the repository. The token should have the following permissions:
  - Actions: Read and Write
  - Administration: Read-only
  - Contents: Read and Write
  - Metadata: Read-only
  - Pull Requests: Read and Write

### Variables
- `MAX_RETRIES`: Maximum number of retries for code repair attempts