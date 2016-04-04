#!/usr/bin/ruby

# Copyright 2016 hidenorly
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'optparse'
require 'kconv'

def getDefaultRoute_Mac
	# -- get default route address
	exec_cmd = "route -n get default 2>/dev/null | grep gateway"
	gateway_addr=""
	IO.popen(exec_cmd, "r",) {|io|
	  gateway_addr=io.gets.to_s.strip
	}
	pos = gateway_addr.index("gateway: ")
	if pos != nil then
		gateway_addr = gateway_addr.slice(pos+9, gateway_addr.length-pos-9)
	end

	return gateway_addr
end

def getDefaultRoute_linux
	# -- get default route address
	exec_cmd = "/sbin/route 2>/dev/null | grep default"
	gateway_addr=""
	IO.popen(exec_cmd, "r",) {|io|
	  gateway_addr=io.gets.to_s.strip
	}

	result = gateway_addr.split(" ")
	gateway_addr = (result.length >= 2) ? result[1] : ""

	return gateway_addr
end


def getDefaultRoute
	gateway = getDefaultRoute_linux()
	if gateway != "" then
		return gateway
	else
		return getDefaultRoute_Mac()
	end
end

# -- get session ID
URI_GET_SESSION_ID = "/index.cgi/reboot_main"
GREP_GET_SESSION_ID = "| grep SESSION_ID"
def getSessionID(ipaddr, userID, password)
	exec_cmd = "curl -u #{userID}:#{password} -s http://#{ipaddr}#{URI_GET_SESSION_ID} #{GREP_GET_SESSION_ID}"

	sessionID=""
	IO.popen(exec_cmd, "r",) {|io|
	  sessionID=io.gets.to_s.strip
	}

	pos = sessionID.index("value='")
	if pos != nil then
		sessionID = sessionID.slice(pos+7, sessionID.length-pos-8)
		pos2 = sessionID.rindex("'", pos)
		sessionID = sessionID.slice(0, pos2)
	end

	return sessionID
end

# --- exec reboot
URI_REQUEST_REBOOT = "/index.cgi/reboot_main_set"
REBOOT_ARG='-F "SESSION_ID='
REBOOT_ARG2='"'
def exec_reboot(ipaddr, userID, password, sessionID)
	exec_cmd = "curl -u #{userID}:#{password} #{REBOOT_ARG}#{sessionID}#{REBOOT_ARG2} -s http://#{ipaddr}#{URI_REQUEST_REBOOT}"
	IO.popen(exec_cmd, "r",) {|io|
		#puts io.gets
	}
end

def getIpAddressList(buf)
	ipAddrs = []

	loop do
		ipAddr = buf.match(/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/)
		if ipAddr != nil then
			ipAddrs << ipAddr[0]
			pos = buf.index(ipAddr[0])
			buf = buf.slice(pos+ipAddr[0].length, buf.length-pos-ipAddr[0].length)
		else
			break
		end
	end

	return ipAddrs
end

def getMacAddressList(buf)
	macAddrs = []

	loop do
		macAddr = buf.match(/([0-9a-f]{2}:){5}[0-9a-f]{2}/)
		if macAddr != nil then
			macAddrs << macAddr[0]
			pos = buf.index(macAddr[0])
			buf = buf.slice(pos+17, buf.length-pos-17)
		else
			break
		end
	end

	return macAddrs
end

URI_GET_CONNETED_DEVICES = "/index.cgi/info_main"
GREP_DEVICES = '| grep "'"<td class='matrix_item'>"'"'

def get_connected_devices(ipaddr, userID, password)
	devices = {}

	exec_cmd = "curl -u #{userID}:#{password} -s http://#{ipaddr}#{URI_GET_CONNETED_DEVICES} #{GREP_DEVICES}"
	result = ""
	IO.popen(exec_cmd, "r",) {|io|
		result = io.gets.to_s.strip
	}
	if result.to_s.valid_encoding? then
		ipAddrs = getIpAddressList(result.to_s)
		macAddrs = getMacAddressList(result.to_s)
		if ipAddrs.length == macAddrs.length then
			# parse successful
			(0..(ipAddrs.length-1)).each do |i|
				devices[ macAddrs[i] ] = ipAddrs[i]
			end
		end
	end

	return devices
end

URI_GET_WAN_IP = "/index.cgi/info_main"
WANIP_MARKER1 = "WAN側IPアドレス"
WANIP_MARKER2 = "<td class='small_item_td2' colspan='2'>"
WANIP_MARKER3 = "</td>"
def get_WAN_IPAddress(ipaddr, userID, password)
	STDOUT.sync = true

	exec_cmd = "curl -u #{userID}:#{password} -s http://#{ipaddr}#{URI_GET_CONNETED_DEVICES}"
	result = ""
	found = false
	IO.popen(exec_cmd, "r",).each do |line|
		line = line.to_s.toutf8()
		if found then
			pos = line.index(WANIP_MARKER2)
			pos2 = line.index(WANIP_MARKER3)
			if pos && pos2 then
				pos1 = pos+(WANIP_MARKER2.length)
				result = line.slice(pos1, (line.length)-pos1-WANIP_MARKER3.length-1).strip()
				break
			end
		end
		found = true if line.to_s.index(WANIP_MARKER1)
	end

	return result
end


options = {
	:command => "reboot",
	:ipaddr => "192.168.10.1",
	:userID => "admin",
	:password => "",
	:reboot => nil
}

options[:ipaddr] = getDefaultRoute()

opt_parser = OptionParser.new do |opts|
	opts.banner = "Usage: -p password (mandatory)"
	opts.on_head("Aterm Utility Copyright 2016 hidenorly")
	opts.version = "1.0.0"

	opts.on("-c", "--command=", "set command: reboot|listDevices|showWANIP(default:--comand=#{options[:command]})") do |command|
		options[:command] = command
	end

	opts.on("-i", "--ipaddr=", "set Aterm IP Address (default:--ipaddr=#{options[:ipaddr]})") do |ipaddr|
		options[:ipaddr] = ipaddr
	end

	opts.on("-u", "--user=", "set userID (default:--user=#{options[:userID]})") do |userID|
		options[:userID] = userID
	end

	opts.on("-p", "--password=", "set password (mandatory)") do |password|
		options[:password] = password
	end

	opts.on("-r", "--reboot=", "set specified Aterm with mac address for -c reboot (same userID/password required among router & converter)") do |reboot|
		options[:reboot] = reboot
	end
end.parse!

if options[:password] == "" then
	puts "Specify --password="
	exit(-1)
end

sessionID = getSessionID(options[:ipaddr], options[:userID], options[:password])

case options[:command]
when "reboot"
	# reboot Aterm
	if options[:reboot] == nil then
		# reboot Aterm router
		exec_reboot(options[:ipaddr], options[:userID], options[:password], sessionID)
	else
		# reboot Aterm specified with MAC Address
		devices = get_connected_devices(options[:ipaddr], options[:userID], options[:password])
		if devices.has_key?( options[:reboot] ) then
			targetIP = devices[ options[:reboot] ]
			sessionID = getSessionID(targetIP, options[:userID], options[:password])
			exec_reboot(targetIP, options[:userID], options[:password], sessionID)
		else
			puts "Mac Address #{options[:reboot]} is not found. Use --command=listDevices"
		end
	end
when "showWANIP"
	# Show WAN IP
	puts "WAN ipaddr:#{get_WAN_IPAddress(options[:ipaddr], options[:userID], options[:password])}"
when "listDevices"
	# List connected devices' IP address & MAC Address
	devices = get_connected_devices(options[:ipaddr], options[:userID], options[:password])
	puts "Aterm #{options[:ipaddr]} has folllowing devices:"
	devices.each do |macAddr, ipAddr|
		puts "#{macAddr} #{ipAddr}"
	end
end
