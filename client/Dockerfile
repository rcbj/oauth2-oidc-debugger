FROM ruby:latest
MAINTAINER Robert C. Broeckelmann Jr. <robert@iyasec.io>
WORKDIR /usr/src/app/
COPY Gemfile /usr/src/app/Gemfile
COPY Gemfile.lock /usr/src/app/Gemfile.lock
RUN gem install rails bundler
RUN bundle install
RUN bundle config --global frozen 1
COPY . /usr/src/app
EXPOSE 3000

RUN apt-get update -qq && apt-get install 

#CMD ["rails", "server", "-b", "0.0.0.0" ]
CMD [ "rails", "server" ]
