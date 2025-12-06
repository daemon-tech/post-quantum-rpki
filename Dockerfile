FROM ubuntu:24.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-full \
    python3-pip \
    python3-venv \
    python3-dev \
    git \
    cmake \
    ninja-build \
    build-essential \
    libssl-dev \
    libtls-dev \
    rpki-client \
    rsync \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs from source (required before liboqs-python)
# Using latest stable version that's compatible with liboqs-python 0.14.1
RUN cd /tmp && \
    git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    ninja && \
    ninja install && \
    cd / && rm -rf /tmp/liboqs && \
    ldconfig

# Set LD_LIBRARY_PATH so liboqs shared libraries can be found
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Set working directory
WORKDIR /work

# Copy requirements first for better caching
COPY requirements.txt* ./

# Install Python dependencies
# Note: --break-system-packages is safe in Docker containers (isolated environment)
RUN if [ -f requirements.txt ]; then \
        pip3 install --no-cache-dir --break-system-packages -r requirements.txt; \
    else \
        pip3 install --no-cache-dir --break-system-packages \
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

