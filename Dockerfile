FROM python:3.14.7

# Set the working directory
WORKDIR /app

# Copy requirements first to leverage Docker layer caching
COPY ./requirements.txt /app/requirements.txt

# Install dependencies
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

# Copy the rest of the application code based on your tree
COPY . /app

# Default command for the API service
CMD ["fastapi", "run", "main.py", "--port", "8000"]