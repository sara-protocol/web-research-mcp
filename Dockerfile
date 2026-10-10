FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY src ./src
COPY scripts ./scripts
RUN addgroup -S app && adduser -S app -G app && chown -R app:app /app
USER app
EXPOSE 8787
CMD ["node", "src/server.js"]
