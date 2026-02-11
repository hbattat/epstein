# Use Node.js 20 Alpine for a small footprint
FROM node:20-alpine

# Install FFmpeg for thumbnail generation
RUN apk add --no-cache ffmpeg

# Set working directory
WORKDIR /app

# Copy package files (if any exist, though currently a direct node server)
# COPY package*.json ./
# RUN npm install --production

# Copy application source
COPY . .

# Expose the server port
EXPOSE 3000

# Start the server
CMD ["node", "server.js"]
