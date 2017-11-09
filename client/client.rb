require 'sinatra'
require 'securerandom'

enable :sessions
set :session_secret, '*&(^B234'

GATEWAY = ENV['GATEWAY'] || "http://localhost:8080"
#CLIENT_ID = ENV['CLIENT_ID']
#CLIENT_SECRET = ENV['CLIENT_SECRET']
#REDIRECT_URI = ENV['REDIRECT_URI'] || "http://localhost:3000/callback"
#AUTHORIZE_ENDPOINT = "#{GATEWAY}/authorize"
#TOKEN_ENDPOINT = "#{GATEWAY}/oauth/token"

get("/") do
  @state = SecureRandom.uuid
  session[:state] = @state
	erb :root
end

get("/callback") do
        @code = params[:code]
        @implicit_grant_access_token = params[:access_token]
	erb :root
end
