FROM ubuntu:24.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    cmake \
    build-essential \
    libssl-dev \
    libtls-dev \
    rpki-client \
    rsync \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /work

# Copy requirements first for better caching
COPY requirements.txt* ./

# Install Python dependencies
RUN if [ -f requirements.txt ]; then \
        pip3 install --no-cache-dir -r requirements.txt; \
    else \
        pip3 install --no-cache-dir \
            liboqs-python==0.14.1 \
            matplotlib \
            pandas \
            tqdm; \
    fi

# Copy all project files
COPY . /work/

# Make scripts executable
RUN chmod +x *.sh *.py 2>/dev/null || true

# Default command
CMD ["/bin/bash"]

