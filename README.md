## Sensu-Plugins-splunk

[![Build Status](https://travis-ci.org/sensu-plugins/sensu-plugins-splunk.svg?branch=master)](https://travis-ci.org/sensu-plugins/sensu-plugins-splunk)
[![Gem Version](https://badge.fury.io/rb/sensu-plugins-splunk.svg)](http://badge.fury.io/rb/sensu-plugins-splunk)
[![Dependency Status](https://gemnasium.com/sensu-plugins/sensu-plugins-splunk.svg)](https://gemnasium.com/sensu-plugins/sensu-plugins-splunk)

## Functionality

## Files
 * bin/handler-splunkstorm
 * bin/handler-splunk-hec

## Usage

```
{
  "splunkstorm": {
    "project_id": "12345",
    "access_token": "abcde"
  }
}

{
  "splunk-hec" : {
        "token" : "[your token here]",
        "index" : "[index]",
        "host" : "[splunk host]"
    }

}
```

## Installation

[Installation and Setup](http://sensu-plugins.io/docs/installation_instructions.html)

## Notes