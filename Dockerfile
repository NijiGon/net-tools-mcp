FROM node:18-alpine

RUN apk add --no-cache \
    iputils \
    bind-tools \
    net-tools \
    curl \
    wget \
    whois \
    traceroute \
    openssh-client

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

EXPOSE 3000

CMD ["node", "build/index.js"]
