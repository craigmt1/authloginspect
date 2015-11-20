#!/usr/bin/python

from urllib2 import urlopen
from contextlib import closing
from operator import itemgetter
from os import path
from dateutil import parser
import json, sys, urllib, argparse

ips = set()
allAttempts = []

class loginAttempt:
	def __init__(self, date, ipaddress, username, success=False):
		self.date = str(parser.parse(date))
		self.ipaddress = str(ipaddress)
		self.username = str(username)
		self.success = str(success)
		self.city, self.country, self.latitude, self.longitude = '','','',''
	
	def addLocation(self, location):
		(self.city, self.country, self.latitude, self.longitude) = location
		try:
			self.city, self.country, self.latitude, self.longitude = str(self.city), str(self.country), str(self.latitude), str(self.longitude)
		except:
			self.city, self.country, self.latitude, self.longitude = self.city.encode('utf-8'), self.country.encode('utf-8'), str(self.latitude), str(self.longitude)

	def __str__(self):
		return '\nIP: ' + self.ipaddress +\
			'\nUSERNAME: ' + self.username +\
			'\nDATE: ' + self.date +\
			'\nSUCCESSFUL?: ' + self.success +\
			'\nCITY: ' + self.city +\
			'\nCOUNTRY: ' + self.country +\
			'\nLATITUDE: ' + self.latitude +\
			'\nLONGITUDE: ' + self.longitude

	def toCSV(self):
		return self.ipaddress +\
			',' + self.username +\
			',' + self.date +\
			',' + self.success +\
			',' + self.city +\
			',' + self.country +\
			',' + self.latitude +\
			',' + self.longitude


def getlocation(ip):
	url = 'http://freegeoip.net/json/' + ip
	try:
	    with closing(urlopen(url)) as response:
	        location = json.loads(response.read())
	        return (location['city'], location['country_name'], location['latitude'], location['longitude'])
	except:
	    return (None, None, None, None)

#parse single line to object, collect unique ips
def parseLine(line, validOnly=False, invalidOnly=False):
	datestamp, username, ipaddress, success = '','','', False

	if not validOnly and 'Invalid' in line and 'password' not in line:
		datestamp = line[:15]
		tmp = line[line.index('Invalid') + 13:]
		username = tmp[:tmp.index(' from ')]
		ipaddress = tmp[tmp.index(' from ') + 6:-1]

	elif not invalidOnly and 'Accepted' in line:
		datestamp = line[:15]
		tmp = line[line.index('Accepted') + 22:]
		username = tmp[:tmp.index(' from ')]
		ipaddress = tmp[tmp.index(' from ') + 6:tmp.index(' port')]
		success = True

	#clear unwanted spaces
	if len(username):
		while username[0] == ' ': username = username[1:]

	global ips
	ips.add(ipaddress)
	return loginAttempt(datestamp, ipaddress, username, success)



def main():
	#take arguments
	parser = argparse.ArgumentParser(description='Command Line Arguments')

	parser.add_argument('-f', '--file', type=str, help='An optional input file path for log file')
	parser.add_argument('-o', '--output', type=str, help='An optional output file argument')
	parser.add_argument('-y', '--valid', action='store_true', default=False, help='Output only successful login attempts')
	parser.add_argument('-n', '--invalid', action='store_true', default=False, help='Output only failed login attempts')
	parser.add_argument('-x', '--csv', action='store_true', default=False, help='Format output as CSV')
	parser.add_argument('-s', '--silent', action='store_true', default=False, help='Disable verbose output')
	args = parser.parse_args()

	if args.valid and args.invalid: exit("Filtering both successful and unsuccessful login attempts, nothing to display!")

	f = None
	if args.file:
		try: f = open(args.file, 'r')
		except: exit("Could not load file from path provided")
	else:
		#no file argument provided, check default paths
		paths = ['/var/log/auth.log', '/var/log/secure']
		for p in paths:
			if path.exists(p):
				try: f = open(p, 'r')
				except: exit("Access Denied! " + p)
				break
	if f == None: exit('Failed to load logfile')

	fileout = None
	if args.output:
		try:
			fileout = open(args.output, 'w')
			if args.csv:
				fileout.write('Address,Username,Date,Success?,City,Country,Latitude,Longitude')
		except: exit("Unable to generate output file at path specified.")

    #parse lines to objects
	global allAttempts
	allAttempts = [parseLine(line, args.valid, args.invalid) for line in f]
	f.close()

	#gather location data for ips
	global ips
	ips = dict.fromkeys(ips)
	for ip in ips: ips[ip] = getlocation(ip)

	#add location data to objects
	for attempt in allAttempts:
		if attempt.ipaddress == '': continue
		attempt.addLocation(ips[attempt.ipaddress])

		if args.csv: out = '\n' + attempt.toCSV()
		else: out = str(attempt)

		if not args.silent: print(out)
		if args.output: fileout.write(out)

	if fileout: fileout.close()

if __name__ == "__main__":
	main()
	exit()
