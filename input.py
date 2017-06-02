import csv
import json
import urllib
import urllib2


with open('Addr1.csv') as csvfile:
	rows = csv.reader(csvfile)
	res = list(zip(*rows))


for ip in res:
	print(ip)

if '101.6.53.18' in res:
	print 'yay'