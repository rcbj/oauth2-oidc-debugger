FROM node:12

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY package.json /usr/src/app
RUN npm install && npm cache clean --force 
RUN npm install -g browserify
#RUN npm install -g node-gyp

# If you are building your code for production
# RUN npm ci --only=production

# Bundle app source
COPY public/ /usr/src/app/public/
COPY server.js /usr/src/app
COPY package.json /usr/src/app
COPY src/ /usr/src/app/src/
RUN browserify src/jwks.js -o public/js/jwks.js --debug --standalone jwks
RUN browserify src/debugger.js -o public/js/debugger.js --debug --standalone debug
# RUN browserify src/debugger2.js -o public/js/debugger2.js --debug --standalone debug2
COPY src/debugger2_js.js public/js

EXPOSE 3000
CMD [ "npm", "start" ]
