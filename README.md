# TON Telemetry Service
## Building and running

  - First time: run `./setup.sh` to install required building tools: `docker`, `docker-compose`, `curl`.
  - Set needed environment variables (see [Configuration](#Configuration))
  - Build services: `docker-compose build`.
  - Run services: `docker-compose up -d`.
  - (Optional) Generate SSL certificates: 
    - Connect to nginx container and run CertBot: `docker-compose exec nginx certbot --nginx`.
    - Enter email, agree with EULA, choose DNS name and setup SSL certs.
    - Restart NGINX: `docker-compose restart nginx`.
   - Stop services: `docker-compose down`. Run this command with`-v` flag to clear docker volumes (mongodb, nginx and ssl data).

## Configuration

The service supports the following environment variables for configuration.

- `TON_TELEMETRY_WEBSERVERS_WORKERS` *(default: 1)*

Number of webserver processes.