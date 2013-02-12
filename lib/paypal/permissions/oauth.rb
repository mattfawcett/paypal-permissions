require 'base64'
require 'openssl'
require 'uri'

module Paypal
  module Permissions
    module Oauth
      # Create the X-PP-AUTHORIZATION header
      def generate_signature(token, token_secret, http_method, endpoint)
        raise "Invalid HTTP Method. Valid values: GET, POST, DELETE, UPDATE." unless ['GET','POST','DELETE','UPDATE'].include? http_method

        timestamp = Time.now.to_i.to_s

        query_params = {}
        key = [
          paypal_encode(@password),
          paypal_encode(token_secret),
        ].join("&")

        params = query_params.dup.merge({
          "oauth_consumer_key" => @userid,
          "oauth_version" => "1.0",
          "oauth_signature_method" => "HMAC-SHA1",
          "oauth_token" => token,
          "oauth_timestamp" => timestamp,
        })
        sorted_query_string = params.collect do |key, value|
          "#{key}=#{value}"
        end.sort.join('&')

        base = [
          "POST",
          paypal_encode(endpoint),
          paypal_encode(sorted_query_string)
        ].join("&")
        base = base.gsub /%([0-9A-F])([0-9A-F])/ do
          "%#{$1.downcase}#{$2.downcase}"  # hack to match PayPal Java SDK bit for bit
        end

        digest = OpenSSL::HMAC.digest('sha1', key, base)
        signature = Base64.encode64(digest).chomp
        "timestamp=#{timestamp},token=#{token},signature=#{signature}"
      end

      def paypal_encode(str)
        s = str.dup
        CGI.escape(s).gsub('.', '%2e').gsub('-', '%2d')
      end
    end
  end
end
