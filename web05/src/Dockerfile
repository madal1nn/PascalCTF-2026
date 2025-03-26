FROM node:alpine

WORKDIR /app

COPY package* .
RUN npm install
COPY . .

RUN apk add --no-cache p7zip wget && wget -O /app/public/songs.7z https://music.aitch.me/bl4ckh4tl33tsongs.7z && 7z x /app/public/songs.7z -o/app/public && rm /app/public/songs.7z && apk del wget p7zip
ENTRYPOINT [ "node", "." ]
