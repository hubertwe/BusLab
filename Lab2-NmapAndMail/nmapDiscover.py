#!/usr/bin/python
import subprocess
import time
import re
import json

ports = '1-2048'
ipRange = '156.17.42.0/24'
#ipRange = '10.104.34.192/27'

hostReg = re.compile('Nmap scan report for ([a-z0-9-.]*) \(([0-9.]*)\)')
serviceReg = re.compile('([0-9]*)\/([a-z]*)\s*(open)\s*([a-z]*)\S*\s*(.*)')

hosts = list()
host = dict()
services = list()
service = dict()

def getHost(host):
	matchedHost = hostReg.search(host)
	ip = None
	hostName = None
	if matchedHost :
		hostName =  matchedHost.group(1)
		ip = matchedHost.group(2)
	else :
		raise ValueError
	return hostName, ip

def getServices(host):
	services = list()
	matchedServices = serviceReg.findall(host)
	if matchedServices:
		for serviceIt in matchedServices :
			service['port'] = serviceIt[0]
			service['protocol'] = serviceIt[1]
			service['name'] = serviceIt[3]
			service['description'] = serviceIt[4]
			services.append(service)
	if len(services) == 0:
		raise ValueError
	return services

def saveToFile(hosts):
	file = open('hosts.json', 'wb')
	json.dump(hosts, file)

def splitToHosts(inputStr):
	return inputStr.split('\n\n')

def nmap():
	nmap = subprocess.Popen(['nmap', '-sV', '-p', ports, ipRange], stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=1).communicate()

	hosts = list()
	for hostIt in splitToHosts(nmap[0]) :
		
		print '---------------------------------'
		#print host 
		try:
			host = dict()
			hostname, ip = getHost(hostIt)
			services = getServices(hostIt)
			host['name'] = hostname
			host['ip'] = ip
			host['services'] = services
			hosts.append(host)
			print hostname
			print ip
			print services
		except ValueError:
			print "Blah blah blah...."
			continue
	saveToFile(hosts)

if __name__ == '__main__':
	nmap()
	pass

