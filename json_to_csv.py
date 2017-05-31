import csv
import json
import urllib
import urllib2


with open('test.csv') as csvfile:
	rows = csv.reader(csvfile)
	res = list(zip(*rows))

def cymon(data):
	theJSON = json.loads(data)
	blacklisted_data = theJSON['results']
	blacklisted_ip = open('test.csv','w')
	csvwriter = csv.writer(blacklisted_ip)
	count = 0
	for i in blacklisted_data:
		if count == 0:
			header = i.keys()
			csvwriter.writerow(header)
			count += 1
		csvwriter.writerow(i.values())
	blacklisted_ip.close()
	
def main():
	url = 'https://cymon.io/api/nexus/v1/blacklist/ip/dnsbl/?format=json'
	ipurl = urllib2.urlopen(url)
	print(ipurl.getcode())
	ipdata = ipurl.read()
	cymon(ipdata)

if __name__ == "__main__":
	main()
