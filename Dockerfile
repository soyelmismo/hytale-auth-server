FROM node:20-alpine

WORKDIR /app

# Install unzip for Assets.zip extraction
RUN apk add --no-cache unzip

# Create directories
RUN mkdir -p /app/data /app/assets

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install --omit=dev

# Copy source code
COPY src/ ./src/

# Copy static assets
COPY assets/avatar.js ./assets/
COPY assets/customizer.html ./assets/

EXPOSE 3000

CMD ["node", "src/app.js"]
