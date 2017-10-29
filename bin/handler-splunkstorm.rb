#!/usr/bin/env ruby
#
# This handler logs sensu events to Splunkstorm.
#
# Requires the json gem
# gem install json
#
# Released under the same terms as Sensu (the MIT license); see LICENSE
# for details.

require 'net/https'
require 'json'

API_HOST = 'api.splunkstorm.com'.freeze
API_VERSION = 1
API_ENDPOINT = 'inputs/http'.freeze
URL_SCHEME = 'https'.freeze

module Sensu
  class Handler
    def self.run
      handler = new
      handler.filter
      handler.alert
    end

    def initialize
      @event = JSON.parse(STDIN.read)
    end

    def filter
      if @event['check']['alert'] == false
        puts 'alert disabled -- filtered event ' + [@event['client']['name'], @event['check']['name']].join(' : ')
        exit 0
      end
    end

    def alert
      refresh = (60.fdiv(@event['check']['interval']) * 30).to_i
      # #YELLOW
      if @event['occurrences'] == 1 || @event['occurrences'] % refresh == 0 # rubocop:disable GuardClause
        splunkstorm
      end
    end

    def splunkstorm
      incident_key = @event['client']['name'] + ' ' + @event['check']['name']
      event_params = { sourcetype: 'sensu-server', host: @event['client']['name'], project: settings['splunkstorm']['project_id'] }

      begin
        timeout(3) do
          api_url = "#{URL_SCHEME}://#{API_HOST}"
          api_params = URI.escape(event_params.map { |k, v| "#{k}=#{v}" }.join('&'))
          endpoint_path = "#{API_VERSION}/#{API_ENDPOINT}?#{api_params}"
          uri = URI.parse("#{api_url}/#{endpoint_path}")

          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = true

          request = Net::HTTP::Post.new(url.request_uri, user: 'sensu', password: settings['splunkstorm']['access_token'])
          request.body = @event.to_json
          response = http.request(request)
          puts JSON.parse(response.body)
        end
      rescue Timeout::Error
        puts 'splunkstorm -- timed out while attempting to log incident -- ' + incident_key
      end
    end
  end
end
Sensu::Handler.run
