FROM python:3.11-slim

WORKDIR /app

# Install system packages required for dependencies and nuclei
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libffi-dev \
    git \
    curl \
    ca-certificates \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Copy python dependencies
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY . .

# Download & initialize Nuclei scanner binary and templates
RUN python install_nuclei.py

# Add bin/ directory to PATH so nuclei is globally executable
ENV PATH="/app/bin:${PATH}"

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
