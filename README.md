# Net Tools HTTP API

HTTP-based network diagnostic tools with OpenAPI specification.

## Installation

```bash
npm install
npm run build
```

## Usage

### Local

```bash
npm start
```

### Docker

```bash
docker-compose up -d
```

Server runs on port 3000 (configurable via PORT env variable).

## OpenAPI Specification

Access the OpenAPI spec at: `http://localhost:3000/openapi.json`

## API Endpoints

All endpoints accept POST requests with JSON body:

- `POST /ping` - Test host connectivity
- `POST /nslookup` - DNS lookup
- `POST /netstat` - Network connections/statistics
- `POST /telnet` - Test TCP port connectivity
- `POST /ssh` - Execute remote SSH commands
- `POST /traceroute` - Trace route to host
- `POST /curl` - HTTP request
- `POST /wget` - Download file
- `POST /whois` - WHOIS lookup

## Example

```bash
curl -X POST http://localhost:3000/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "google.com", "count": 4}'
```
