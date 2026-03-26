# Vulnerable Dockerfile snippet
FROM docker:stable
WORKDIR /app
COPY . /app
# The following line is the vulnerability
CMD ["docker", "run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "your-image-name"]
