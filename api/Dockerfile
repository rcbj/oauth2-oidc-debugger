FROM ubuntu:latest

ARG CONFIG_FILE

# replace shell with bash so we can source files
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

# Create app directory
WORKDIR /usr/src/app

RUN apt-get update
RUN apt-get -y install curl \
        jq \
        wget \
        unzip \
        util-linux \ 
        bsdextrautils
 
# Install NVM
ENV NVM_DIR /usr/local/nvm
ENV NODE_VERSION=24.16.0
RUN mkdir -p ${NVM_DIR}
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.5/install.sh | bash

# Load NVM and install Node.js
RUN . $NVM_DIR/nvm.sh && nvm version && echo -e ". $NVM_DIR/nvm.sh\nexport PATH=\$NVM_DIR/versions/node/\$(nvm version)/bin:\$PATH" >> ~/.bashrc
RUN cat ~/.bashrc

RUN source $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default

# Symlink the node/npm/npx binaries nvm actually installed into a dir that is
# always on PATH. This avoids "npm: command not found" when the hardcoded
# v$NODE_VERSION path below ever drifts from the directory nvm created.
RUN source $NVM_DIR/nvm.sh \
    && ln -sf "$(dirname "$(nvm which default)")"/* /usr/local/bin/

# add node and npm to path so the commands are available
ENV NODE_PATH $NVM_DIR/versions/node/v$NODE_VERSION/lib/node_modules
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH

# confirm installation
RUN node -v
RUN npm -v

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY api/package*.json ./
RUN npm -version
RUN npm install
# If you are building your code for production
# RUN npm ci --only=production

# Bundle app source
COPY api/. .
COPY api/env/ /usr/src/app/env/
COPY common/data.js .

# ---- Code coverage (opt-in) ----
# When built with --build-arg COVERAGE=true, install c8 so the coverage compose
# override can launch the server under it. No-op for the default build.
ARG COVERAGE=false
RUN if [ "$COVERAGE" = "true" ]; then npm install -g c8; fi

EXPOSE 4000
CMD [ "npm", "start" ]
