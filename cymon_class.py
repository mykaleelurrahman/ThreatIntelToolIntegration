import csv
list = {u'updated': u'2017-06-01T02:09:40Z', u'addr': u'8.8.8.8', u'created': u'2015-03-23T12:03:42Z', u'sources': [u'bambenekconsulting.com', u'safeweb.norton.com', u'malwr.com', u'virustotal.com', u'urlquery.net', u'google safebrowsing', u'phishtank'], u'urls': u'https://cymon.io/api/nexus/v1/ip/8.8.8.8/urls', u'domains': u'https://cymon.io/api/nexus/v1/ip/8.8.8.8/domains', u'events': u'https://cymon.io/api/nexus/v1/ip/8.8.8.8/events'}

print list[u'sources']
with open('getthistoworkq.csv', 'wb') as outfile:
		write = csv.writer(outfile,delimiter = ',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
		write.writerow(['updated','addr','created','urls','domains','events'])
		write.writerow([list[u'updated'],list[u'addr'],list[u'created'],list[u'urls'],list[u'domains'],list[u'events']])