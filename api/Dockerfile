FROM node:lts

ARG CONFIG_FILE

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY api/package*.json ./

RUN npm install
# If you are building your code for production
# RUN npm ci --only=production

# Bundle app source
COPY api/. .
COPY api/env/ /usr/src/app/env/
COPY common/data.js .
RUN ls
RUN ls env

EXPOSE 4000
CMD [ "npm", "start" ]
