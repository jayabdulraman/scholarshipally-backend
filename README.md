# scholarshipally-backend

This is the backend that enables data persistence and chat history for [ally](https://github.com/jayabdulraman/scholarshipally-frontend).

## Built with:
- Django
- Django-restframework
- SQlite for dev and Postgres database for prod.

## Getting Started

- Clone the dev repo.
- Create a virtualenv and pip install -r requirements.txt
- Install Qdrant with docker, [see here](https://qdrant.tech/documentation/quickstart/).
- Add your openai key, qdrant key (optional), and DEVELOPMENT_MODE='True' to .env file
- Run upsert-data-to-vector.ipynb to upsert data to Qdrant vector
- Run your django server
- Go to [frontend](https://github.com/jayabdulraman/scholarshipally-frontend) to setup.
