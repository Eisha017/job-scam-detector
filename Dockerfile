# Dockerfile for Hugging Face Spaces deployment
# HF Spaces expects the app to listen on port 7860 by convention.

FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (better Docker layer caching -- only reinstalls
# if requirements.txt changes, not on every code edit)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# spaCy's English model isn't in requirements.txt by default install --
# make sure it's downloaded during the image build
RUN python -m spacy download en_core_web_sm

# Copy the rest of the project
COPY . .

# Hugging Face Spaces routes traffic to port 7860 by default
EXPOSE 7860

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860"]
