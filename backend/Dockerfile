FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directories
RUN mkdir -p /app/keys /app/media

# Generate RSA keys if not present
RUN python3 << 'EOF'
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

key_dir = '/app/keys'
os.makedirs(key_dir, exist_ok=True)

priv_path = f'{key_dir}/private.pem'
pub_path  = f'{key_dir}/public.pem'

if not os.path.exists(priv_path) or not os.path.exists(pub_path):
    print('Generating RSA key pair...')
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    with open(priv_path, 'wb') as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
    
    with open(pub_path, 'wb') as f:
        f.write(private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print('Keys generated successfully')
else:
    print('Keys already exist')
EOF

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Run
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
