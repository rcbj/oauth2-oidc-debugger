FROM node:12

ARG CONFIG_FILE
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
COPY env/ /usr/src/app/env/
COPY server.js /usr/src/app
COPY package.json /usr/src/app
RUN true
COPY src/ /usr/src/app/src/
RUN true
COPY src/env/ /usr/src/app/public/js/env/
RUN browserify src/jwks.js -o public/js/jwks.js --debug --standalone jwks
RUN browserify src/debugger.js -o public/js/debugger.js --debug --standalone debug
RUN browserify src/token_detail.js -o public/js/token_detail.js --debug --standalone token_detail
RUN browserify src/debugger2.js -o public/js/debugger2.js --debug --standalone debugger2 -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/userinfo.js -o public/js/userinfo.js --debug --standalone userinfo -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
#COPY src/debugger2_js.js public/js

EXPOSE 3000
CMD [ "npm", "start" ]
