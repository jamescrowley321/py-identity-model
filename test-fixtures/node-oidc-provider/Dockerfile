FROM node:20-alpine

WORKDIR /app

# Copy package files and install production dependencies only
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev 2>/dev/null || npm install --omit=dev

# Copy application code
COPY provider.js .

# Run as non-root user (built-in node user in alpine image)
USER node

EXPOSE 3000

CMD ["node", "provider.js"]
