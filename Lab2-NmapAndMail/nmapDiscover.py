#!/usr/bin/python
import subprocess
import time
import re
import json
import sys

hostReg = re.compile('Nmap scan report for ([a-z0-9-.]*) \(([a-z0-9-.]*)\)')
serviceReg = re.compile('([0-9]*)\/([a-z\-\?]+) *(open) *([a-z]*) *(.*)?')

class bcolors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'

def loadVulnerableServicesLists(filename):
	print bcolors.GREEN +"Loading vulnerable services list from: " + filename + " ..." + bcolors.END
	file = open(filename, 'r')
	vServices = json.loads(file.read())
	print bcolors.RED + "List of vulnerable services:" + bcolors.END
	for service in vServices:
		print "\t"+service
	return vServices

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
			service = dict()
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

def nmap(ipRange, ports, simulateNmap = False):
	print bcolors.GREEN + "Starting nmap scan for " + bcolors.END
	print "\tNetwork:\t\t" + bcolors.BLUE + ipRange + bcolors.END
	print "\tPort range:\t\t" + bcolors.BLUE + ports + bcolors.END
	nmap = list()

	if not simulateNmap:
	
		nmap = subprocess.Popen(['nmap', '-sV', '-p', ports, ipRange], stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=1).communicate()
	
	else:
	
		print bcolors.YELLOW + "WARNING: Nmap will be simulated by reading exampleNmapDump.txt file..." + bcolors.END
		file = open ('exampleNmapDump.txt', 'r')
		nmap.append(file.read())
	
	hosts = list()
	for hostIt in splitToHosts(nmap[0]) :
		#print '---------------------------------' 
		try:
			host = dict()
			services = list()
			hostname, ip = getHost(hostIt)
			services = getServices(hostIt)
			host['name'] = hostname
			host['ip'] = ip
			host['services'] = services
			hosts.append(host)
		except ValueError:
			continue
	saveToFile(hosts)
	return hosts

def searchForVulnerableServices(hosts, servicesDefinition):
	for host in hosts:
		for hostService in host['services']:
			for vulService in servicesDefinition:
				if vulService == hostService['description']:
					print bcolors.RED + "ALERT! WOAH! Easy! Vulnerable service was detected" + bcolors.END
					print host['name'] + "(" + host['ip'] + ") " + hostService['name']+ ":" + hostService['port'] + " " + hostService['description']
			
def printHelp():
	print "Usage: " + bcolors.GREEN + sys.argv[0] + bcolors.END + " ipRange portsRange [sim]"
	print "\t\t ipRange\t - range of ip adresses to be scanned"
	print "\t\t portsRange\t - range of ports to be scanned on every host"
	print "\t\t sim\t\t - [optional] read Nmap results from instead of running real one (for testing purposes)" 


if __name__ == '__main__':
	if len(sys.argv) < 3 :
		printHelp()
		sys.exit(1)
	ipRange = sys.argv[1]
	ports = sys.argv[2]
	if len(sys.argv) == 4:
		simulate = sys.argv[3]
	else:
		simulate = ''

	vulnerableServices = list()
	vulnerableServices = loadVulnerableServicesLists('services.json')
	hosts = list()
	if simulate == 'sim':
		sim = True
	else:
		sim = False

	hosts = nmap(ipRange, ports, sim)
	searchForVulnerableServices(hosts, vulnerableServices)