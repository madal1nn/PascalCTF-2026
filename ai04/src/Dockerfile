FROM node:alpine

WORKDIR /app

COPY package* .
RUN npm install

COPY . .

ENTRYPOINT [ "node", "." ]
