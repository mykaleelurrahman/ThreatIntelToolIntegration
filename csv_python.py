import csv
import json
import urllib
import urllib2


with open('ipinput.csv') as csvfile:
	readCSV = csv.reader(csvfile, delimiter = ',')
	data  = list(readCSV)
	row_count = len(data) 
	print (row_count)
	ips = []
	ips.extend(data)
	

def cymon(data):
	theJSON = json.loads(data)
	print theJSON
	for i in theJSON:
		print i, theJSON[i]
		with open('test1.csv', 'ab') as outfile:
			write = csv.writer(outfile,delimiter = ',')
			write.writerow([i,theJSON[i]])

		
	
def main():
	i = 0
	for j in range(0,row_count):
		url = 'https://cymon.io/api/nexus/v1/ip/' + str(ips[j][i])
		print(url)
		try:
			ipurl = urllib2.urlopen(url)
			print(ipurl.getcode())
			ipdata = ipurl.read()
			cymon(ipdata)
		except:
			continue

if __name__ == "__main__":
	main()