FROM node:lts

ARG CONFIG_FILE
# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY client/package.json /usr/src/app
RUN npm install && npm cache clean --force 
RUN npm install -g browserify
#RUN npm install -g node-gyp

# If you are building your code for production
# RUN npm ci --only=production

# Bundle app source
COPY client/public/ /usr/src/app/public/
#COPY dist/ /usr/src/app/public/dist/
COPY client/src/env/ /usr/src/app/env/
COPY client/server.js /usr/src/app
COPY client/package.json /usr/src/app
RUN true
COPY client/src/ /usr/src/app/src/
RUN true
COPY client/src/env/ /usr/src/app/public/js/env/
COPY common/data.js /usr/src/app/src
RUN browserify src/jwks.js -o public/js/jwks.js --debug --standalone jwks -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/debugger.js -o public/js/debugger.js --debug --standalone debug -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/token_detail.js -o public/js/token_detail.js --debug --standalone token_detail -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/debugger2.js -o public/js/debugger2.js --debug --standalone debugger2 -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/userinfo.js -o public/js/userinfo.js --debug --standalone userinfo -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/introspection.js -o public/js/introspection.js --debug --standalone introspection -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]

RUN browserify src/logout.js -o public/js/logout.js --debug --standalone logout -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
#COPY src/debugger2_js.js public/js

EXPOSE 3000
CMD [ "npm", "start" ]
