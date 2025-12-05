FROM node:18-alpine

# Install network tools
RUN apk add --no-cache \
    iputils \
    bind-tools \
    net-tools \
    curl \
    wget \
    openssh-client \
    traceroute \
    whois

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 3000

CMD ["npm", "run", "dev"]
