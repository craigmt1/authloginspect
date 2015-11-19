#!/usr/bin/python

from urllib2 import urlopen
from contextlib import closing
from operator import itemgetter
from os import path
from dateutil import parser
import json, sys, urllib, argparse



#takes two date strings, returns most recent
def mostRecent(d1, d2):
	try:
		if parser.parse(d1) > parser.parse(d2):
			return d1
	except:
		pass
	return d2


def getlocation(ip):
	url = 'http://freegeoip.net/json/' + ip
	try:
	    with closing(urlopen(url)) as response:
	        location = json.loads(response.read())
	        coordinates = ''
	        try: coordinates = str(location['latitude']) + ', ' + str(location['longitude'])
	    	except: pass
	        return (location['city'], location['country_name'], coordinates)
	except:
	    return None


def main():

	#take arguments
	parser = argparse.ArgumentParser(description='Command Line Arguments')

	parser.add_argument('-f', '--file', type=str, help='An optional input file path for log file')
	parser.add_argument('-o', '--output', type=str, help='An optional output file argument')
	parser.add_argument('-a', '--attempts', type=int, help='Limit output to multiple attempts only')
	parser.add_argument('-v', '--valid', action='store_true', default=False, help='Output successful login attempts instead of unsuccessful')
	args = parser.parse_args()

	filterAttempts = 0
	if args.attempts: filterAttempts = args.attempts

	f = None
	if args.file:
		try: f = open(args.file, 'r')
		except: exit("Could not load file from path provided")
	else:
		#no file argument provided
		paths = ['/var/log/auth.log', '/var/log/secure']
		for p in paths:
			if path.exists(p):
				try: f = open(p, 'r')
				except: exit("Access Denied! " + p)
				break
	if f == None: exit('Failed to load logfile')

	fileout = None
	if args.output:
		try: fileout = open(args.output, 'w')
		except: exit("Unable to generate output file at path specified.")

	linesofinterest = dict()
	for line in f:
		if not args.valid and 'Invalid' in line:
			datestamp = line[:15]
			tmp = line[line.index('Invalid') + 13:]
			username = tmp[:tmp.index(' from ')]
			ipaddress = tmp[tmp.index(' from ') + 6:-1]
			if ipaddress not in linesofinterest:
				linesofinterest.update({ipaddress:(username, 1, datestamp)})
			else:
				inc = linesofinterest[ipaddress]
				datestamp = mostRecent(inc[2], datestamp)
				inc = (inc[0], inc[1] + 1, datestamp)
				linesofinterest[ipaddress] = inc

		elif args.valid and 'Accepted' in line:
			datestamp = line[:15]
			tmp = line[line.index('Accepted') + 22:]
			username = tmp[:tmp.index(' from ')]
			ipaddress = tmp[tmp.index(' from ') + 6:tmp.index(' port')]
			while username[0] == ' ': username = username[1:]
			if ipaddress not in linesofinterest:
				linesofinterest.update({ipaddress:(username, 1, datestamp)})
			else:
				inc = linesofinterest[ipaddress]
				datestamp = mostRecent(inc[2], datestamp)
				inc = (inc[0], inc[1] + 1, datestamp)
				linesofinterest[ipaddress] = inc
	f.close()

	linesofinterest = [(ip, linesofinterest[ip][0], linesofinterest[ip][1], linesofinterest[ip][2]) for ip in linesofinterest if linesofinterest[ip][1] > filterAttempts]
	linesofinterest = sorted(linesofinterest,key=itemgetter(2),reverse=True)

	for line in linesofinterest:
		(ip, username, attempts, last) = line
		(city, country, coordinates) = getlocation(ip)

		info = [\
			('\nATTEMPTS:\t', attempts),\
			('\nLAST    :\t', last),\
			('\nIP ADDR: \t', ip),\
			('\nUSERNAME:\t', username),\
			('\nCITY:    \t', city),\
			('\nCOUNTRY: \t', country),\
			('\nCOORDS:  \t', coordinates)
		]

		out = ''
		for o in info:
			try: out += o[0] + str(o[1])
			except: out += o[0] + o[1]

		print(out)
		if fileout:
			try: fileout.write(out + '\n')
			except UnicodeEncodeError: fileout.write(out.encode('utf-8').strip() + '\n')

	if fileout: fileout.close()
	exit()

if __name__ == "__main__":
	main()
