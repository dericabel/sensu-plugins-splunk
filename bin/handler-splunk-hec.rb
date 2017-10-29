#!/usr/bin/env ruby
#
# Splunk HTTP Event Collector handler which ships events as 
# they occur to Splunks HTTP Event Collector.
#
# Released under the same terms as Sensu (the MIT license); see LICENSE
# for details.


require 'sensu-handler'
require 'net/https'
require 'timeout'
require 'uri'
require 'json'
require 'sensu-plugin/utils'
require 'mixlib/cli'


class SplunkHec < Sensu::Handler
  option :json_config,
         description: 'Configuration name',
         short: '-j <config-name>',
         long: '--json <config-name>',
         default: 'splunk-hec'

  def handle
    @json_config = settings[config[:json_config]]
    @json_config['sourcetype'] = "sensu-events" if @json_config['sourcetype'].nil? || @json_config['sourcetype'].empty?
    @json_config['ssl'] = true if @json_config['ssl'].nil? || @json_config['ssl'].empty?
    @json_config['endpoint'] = "services/collector/event" if @json_config['endpoint'].nil? || @json_config['endpoint'].empty?
    @json_config['port'] = "8088" if @json_config['port'].nil? || @json_config['port'].empty?
    @proto = "http"

    if @json_config['ssl']
      @proto = "https"
    end

    if @event['check']['alert'] == false
      puts 'alert disabled -- filtered event ' + [@event['client']['name'], @event['check']['name']].join(' : ')
      exit 0
    end
    if @event['check']['splunk-hec']
      @json_config.merge!(@event['check']['splunk-hec'])
    end

    begin
      Timeout.timeout(3) do
        response = splunk
        if response['code'] == 0
          puts 'splunk accepted event'
        else
          puts 'splunk -- failed to accept event -- ' + incident_key
        end
      end
	rescue Timeout::Error
  	  puts 'splunk -- timed out while attempting to log incident -- ' + incident_key
	end
  end

  def splunk
    incident_key = @event['client']['name'] + ' ' + @event['check']['name']
  	payload = { sourcetype: @json_config['sourcetype'], host: @event['client']['name'], time: @event['timestamp'], event: @event }

	uri = URI.parse("#{@proto}://#{@json_config['host']}:#{@json_config['port']}/#{@json_config['endpoint']}")
	http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    request = Net::HTTP::Post.new(uri.request_uri, 'Authorization' => "Splunk #{@json_config['token']}", 'Content-Type' => 'application/json')
    request.body = payload.to_json
    response = http.request(request)
    JSON.parse(response.body)

  end
end