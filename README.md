# scholarshipally-backend

This is the backend that enables data persistence and chat history for [https://github.com/jayabdulraman/scholarshipally-frontend](ally).

## Built with:
- Django
- Django-restframework
- Postgres database

## Getting Started

- Clone this repo
- Create a virtualenv and pip install -r requirements.txt
- Install Qdrant with docker, [https://qdrant.tech/documentation/quickstart/](see here).
- Add your openai key, qdrant key (optional), and DEVELOPMENT_MODE='True' to .env file
- Run upsert-data-to-vector.ipynb to upsert data to Qdrant vector
- Run your django server
- Go to [https://github.com/jayabdulraman/scholarshipally-frontend](frontend) to setup.
