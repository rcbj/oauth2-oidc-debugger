require 'sinatra'
require 'securerandom'
require 'json'
require 'rest-client'

enable :sessions
set :session_secret, '*&(^B234'

GATEWAY = ENV['GATEWAY'] || "http://localhost:8080"

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

post("/token") do
	begin
		grant_type = params[:grant_type]
      		token_endpoint = params[:token_endpoint]
      		client_id = params[:client_id]
      		client_secret = params[:client_secret]
 		redirect_uri = ""
		code = ""
		username = ""
		password = ""
		if grant_type == "authorization_code"
      			code = params[:code]
			redirect_uri = params[:redirect_uri]
		end
		if grant_type == "password"
			username = params[:username]
			password = params[:password]
		end
      		scope = params[:scope]
		if scope == nil
			scope = ""
		end
                resource = params[:resource]
                if resource == nil
                	resource = ""
		end
		sslValidate = params[:sslValidate]
		if sslValidate == nil
			sslValidate = false
		elsif sslValidate == "false"
			sslValidate = false
		elsif sslValidate == "true"
			sslValidate = true
		else
			sslValidate = false
		end
		puts "token_endpoint=" + token_endpoint
                puts "client_id=" + client_id
                puts "client_secret=" + client_secret
		puts "code=" + code
 		puts "grant_type=" + grant_type
		puts "redirect_uri=" + redirect_uri
		puts "scope=" + scope
		puts "resource=" + resource
		puts "sslValidate=" + sslValidate.to_s
		parameterObject={}
		if grant_type == "authorization_code"
      			parameterObject = { 
				grant_type: grant_type,
				client_id: client_id,
				client_secret: client_secret,
				code: code,
				redirect_uri: redirect_uri
			}
		elsif grant_type == "client_credentials"
			parameterObject =  {
				grant_type: grant_type,
				client_id: client_id,
				client_secret: client_secret
			}
		elsif grant_type == "password"
			parameterObject = {
				grant_type: grant_type,
				client_id: client_id,
				client_secret: client_secret,
				username: username,
				password: password
			}
                end
		if resource != ""
			parameterObject[:resource] = resource
		end
		if scope != ""
			parameterObject[:scope] = scope
		end
                puts "parameterObject=" + parameterObject.to_s
                api_result = RestClient::Request.execute(method: :post, url: params[:token_endpoint], payload: parameterObject, verify_ssl: sslValidate)
        	oauth2_token_response = JSON.parse(api_result)
		puts api_result
		content_type :json
        	api_result
	rescue RestClient::ExceptionWithResponse => e
        	puts "An exception occured: " + e.message
		puts "Stacktrace: " + e.backtrace.inspect
		status e.response.code
		content_type :json
		e.response.body
	rescue Exception => e
		puts "Exception Message: " + e.message
		status 500
		content_type :json
		{
			code: "500",
			error: e.message
		}.to_json
	end
end
