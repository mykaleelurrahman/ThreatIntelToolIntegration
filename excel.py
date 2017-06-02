import csv
array =[
        {
            "title": "Malware reported by Google SafeBrowsing",
            "description": "Domain: 1suckhoe.com",
            "details_url": 'null',
            "created": "2017-06-01T00:19:58Z",
            "updated": "2017-06-01T00:19:58Z",
            "tag": "malware"
        },
        {
            "title": "Phishing reported by Google SafeBrowsing",
            "description": "Domain: www.ffaceebook.xyz",
            "details_url": 'null',
            "created": "2017-05-17T21:21:40Z",
            "updated": "2017-05-17T21:21:40Z",
            "tag": "phishing"
        },
        {
            "title": "Phishing reported by Google SafeBrowsing",
            "description": "Domain: ffaceebook.xyz",
            "details_url": 'null',
            "created": "2017-05-17T21:21:18Z",
            "updated": "2017-05-17T21:21:18Z",
            "tag": "phishing"
        },
        {
            "title": "Malware reported by Google SafeBrowsing",
            "description": "Domain: ylhy1128.f3322.org",
            "details_url": 'null',
            "created": "2017-05-13T20:45:31Z",
            "updated": "2017-05-13T20:45:31Z",
            "tag": "malware"
        },
        {
            "title": "Phishing reported by Google SafeBrowsing",
            "description": "Domain: www.amzipalq.com",
            "details_url": 'null',
            "created": "2017-05-13T20:39:53Z",
            "updated": "2017-05-13T20:39:53Z",
            "tag": "phishing"
        },
        {
            "title": "Malicious activity reported by urlquery.net",
            "description": "Posted: 2017-05-10 10:40:20\nIDS Alerts: 0\nURLQuery Alerts: 1\nBlacklists: 0\nMalicious page URL: http://www.amzipalq.com/",
            "details_url": "http://urlquery.net/report.php?id=1494403426991",
            "created": "2017-05-10T08:40:10Z",
            "updated": "2017-05-10T08:40:10Z",
            "tag": "malicious activity"
        },
        {
            "title": "Malicious activity reported by urlquery.net",
            "description": "Posted: 2017-05-10 10:12:10\nIDS Alerts: 0\nURLQuery Alerts: 0\nBlacklists: 1\nMalicious page URL: http://totoo.otzo.com",
            "details_url": "http://urlquery.net/report.php?id=1494401737638",
            "created": "2017-05-10T08:12:14Z",
            "updated": "2017-05-10T08:12:14Z",
            "tag": "malicious activity"
        },
        {
            "title": "Phishing reported by Google SafeBrowsing",
            "description": "Domain: appleid-manage-photo.com",
            "details_url": 'null',
            "created": "2017-05-09T21:28:06Z",
            "updated": "2017-05-09T21:28:06Z",
            "tag": "phishing"
        },
        {
            "title": "Phishing reported by Google SafeBrowsing",
            "description": "Domain: retoliko.club",
            "details_url": 'null',
            "created": "2017-05-05T20:39:14Z",
            "updated": "2017-05-05T20:39:14Z",
            "tag": "phishing"
        },
        {
            "title": "Malicious activity reported by urlquery.net",
            "description": "Posted: 2017-05-04 12:14:42\nIDS Alerts: 0\nURLQuery Alerts: 1\nBlacklists: 0\nMalicious page URL: http://retoliko.club",
            "details_url": "http://urlquery.net/report.php?id=1493890691350",
            "created": "2017-05-04T10:14:29Z",
            "updated": "2017-05-04T10:14:29Z",
            "tag": "malicious activity"
        }
    ]


with open('cymon_threats.csv', 'wb') as outfile:
		write = csv.writer(outfile,delimiter = ',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
		write.writerow(['title','description','details_url','created','updated','tag'])
		for d in array:
			write.writerow([d['title'],d['description'],d['details_url'],d['created'],d['updated'],d['tag']])
