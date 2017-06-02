import argparse
import csv
from os import listdir
from os.path import isfile, isdir
import re
from sys import exit
import time
import requests
import timeit
from operator import itemgetter
import json

class OutputFile:
    def header(self, var=""):
        raise NotImplementedError
    def footer(self, var=""):
        raise NotImplementedError
    def add_data(self,data):
        if not data in self.data:
            self.data.append(data)
    def out(self):
        raise NotImplementedError

class OutputTemplate(OutputFile):
    def header(self):
        return """<html>
                    <head>
                        <title>IOC Check Report</title>
                            <script type="text/javascript">
                                function _toggleDetails(elmnts, display) {
                                    for (i = 0; i < elmnts.length; i++) {
                                        elmnts[i].setAttribute('style', 'display: '+display);
                                    }
                                }
                                function toggleDetails(cname) {
                                    elmnts = document.getElementsByClassName("domains_"+cname);
                                    btn = document.getElementsByClassName("toggle_"+cname)[0];
                                    if(elmnts[0].style.display == "none") {
                                        btn.value = "Hide Details";
                                        _toggleDetails(elmnts, 'block');
                                    }
                                    else {
                                        btn.value = "Show Details";
                                        _toggleDetails(elmnts, 'none');
                                    }
                                }
                                function _toggleButtons(textval) {
                                    btns = document.getElementsByClassName("toggle");
                                    for (i = 0; i < btns.length; i++) {
                                        btns[i].value = textval;
                                    }
                                }
                                function toggleAll() {
                                    elmnts = document.getElementsByClassName("domains");
                                    btn = document.getElementById("toggle_all");
                                    if (btn.value == "Show All") {
                                        btn.value = "Hide All";
                                        _toggleDetails(elmnts,'block');
                                        _toggleButtons('Hide Details');
                                    }
                                    else {
                                        btn.value = "Show All";
                                        _toggleButtons('Show Details');
                                        _toggleDetails(elmnts,'none');
                                    }
                                }
                                function markChecked(rid) {
                                    elmnt = document.getElementById(rid);
                                    elmnt.setAttribute('style','display: none');
                                }
                            </script>
                        <style type="text/css">
                            .center {
                                text-align: center;
                            }
                        </style>
                    </head>

                    <body>""".encode('utf-8')

    def footer(self):
        return """  </body>
                </html>""".encode('utf-8')

    def __init__(self, fname):
        self.data = []
        self.fname = fname

    def out(self):
        with open(self.fname, "w",newline='') as f:
            f.write(self.header().decode('utf-8'))
            ips = [ip for ip in self.data if isinstance(ip,IPAddress)]
            domains = [d for d in self.data if not d in ips]

            try:
                tmp = [[int(ip.ip.split(".")[0]),int(ip.ip.split(".")[1]),int(ip.ip.split(".")[2]),int(ip.ip.split(".")[3]),ip] for ip in ips]
                sorted_tmp = sorted(tmp,key=itemgetter(0,1,2,3))
                ips = [itm[4] for itm in sorted_tmp]
            except:
                pass

            if ips:
                ips_out = OutputIPs(ips).out()
                f.write(ips_out)
            #if domains:
            #    domains_out =  OutputDomains(domains).out()
            #    f.write(domains_out)
            f.write(self.footer().decode('utf-8'))

class OutputIPs(OutputFile):
    def __init__(self,ips):
        self.data = ips

    def header(self,var=""):
        return """      <h3>IP Addresses: {0}</h3>
                            <table cellspacing="5" cellpadding="5" border="1" border-width="1px" id="mtable">
                                <tr>
                                    <td>IP Address</td>
                                    <td>Blacklists</td>
                                    <td style="width: 15%;">rDNS</td>
                                    <td>ISP</td>
                                    <td>Country</td>
                                    <td>ASN Owner</td>
                                    <td>Domains (URLVoid)</td>
                                    <td>Domains (VirusTotal)</td>
                                    <td><input type="button" id="toggle_all" class="center" value=\"Show All\" onclick=javascript:toggleAll()></td>
                                </tr>
        """.format(var)

    def out(self):
        strng = self.header(len(self.data))
        for ip in self.data:
            try:
                urlvoid_count = ip.urlvoid['count']
                urlvoid_domains = ip.urlvoid['domains']
            except:
                urlvoid_count = ["N/A"]
                urlvoid_domains = [["N/A"]]
            # IPVoid information
            strng += '<tr id="'+ip.ip+'" class="ioc">'
            strng += '<td><a href="http://www.ipvoid.com/scan/' + ip.ip + '">' + ip.ip + '</a>'
            strng += "</td>"
            strng += '<td class="center">' + ip.blist + '</td>'
            strng += '<td>' + ip.rdns + '</td>'
            strng += '<td>' + ip.isp + '</td>'
            strng += '<td>'+ip.cntry+'</td>'
            strng += '<td>' + ip.asn + '</td>'

            # URLVoid information
            strng += '<td><div class="center"><a href="http://www.urlvoid.com/ip/' + ip.ip + '">'
            try:
                if not urlvoid_count == "N/A":
                    if not urlvoid_count[0] == 0:
                        strng += str(urlvoid_count[0]) + '</a> (' + str(urlvoid_count[1]) + ' flagged)'
                    else:
                        strng += str(urlvoid_count[0])+'</a>'
                else:
                    strng += "N/A</a>"
                strng += '</div><div class="domains_' + ip.ip + ' domains" style="display: none">'
                if urlvoid_domains and not urlvoid_domains[0] == ["N/A"]:
                    strng += "<hr>"
                    for itm in urlvoid_domains:
                        strng += '<a href="http://www.urlvoid.com/scan/'+itm[0]+'">'+itm[0] + '</a> (' + itm[1] + ')<br>'
                else:
                    strng += ""
            except:
                pass
            strng += "</td>"

            # self.vtotal['urls] = [url, scanner_count,  vt_url]
            # self.vtotal['domains'] = [domain, date, url]]
            # VirusTotal information
            try:
                strng += '<td><div class="center">'
                strng += '<a href="http://www.virustotal.com/en/ip-address/' + ip.ip + '/information/">' + ip.vtotal['domain_count'] + '</a>'
                strng += '</div><div class="domains_' + ip.ip + ' domains" style="display: none">'
            except:
                ip.vtotal = {'domain_count': "ERR"}
            if not ip.vtotal['domain_count'] in ["N/A","ERR"]:
                strng += "<hr/>"
                for itm in ip.vtotal['domains']:
                    try:
                        if itm['last_resolved']:
                            strng += itm['last_resolved'].split(" ")[0] + ' <a href="http://www.virustotal.com/en/domain/' + itm['hostname'] + '/information/">' + itm['hostname'] + '</a><br/>'
                        elif itm['hostname']:
                            strng += '<a href="http://www.virustotal.com/en/domain/' + itm['hostname'] + '/information/">' + itm['hostname'] + '</a><br/>'
                        else:
                            continue
                    except:
                        continue
            else:
                strng += "N/A"
            strng += '</td><td class="center">'
            if (urlvoid_domains and not urlvoid_domains[0] in [["N/A"], 0]) or (not ip.vtotal['domain_count'] == "N/A"):
                strng += "<input type=\"button\" name=\"toggle_det\" class=\"toggle_" + ip.ip + " toggle\" value=\"Show Details\" onclick=javascript:toggleDetails(\"" + ip.ip + "\")>"
            strng += "<input type=\"button\" name=\"mark_chkd\" class=\"mark_"+ip.ip+"\" value=\"Not FP\" onclick=javascript:markChecked(\""+ip.ip+"\")></td>"
            strng += "</tr>\n"
        strng += self.footer()        
        return strng

    def footer(self,var=""):
        return "</table>"

class IOC:
    def update(self):
        raise NotImplementedError()

class IPAddress(IOC):
    def __init__(self, ip, proxy=""):
        self.ip = ip.strip()
        self.proxy = proxy
        self.cntry = ""
        self.blist = ""
        self.isp = ""
        self.asn = ""
        self.rdns = ""

    def __ipvoid(self):
        values = {"ip": self.ip}
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36"}
        r = requests.post("http://www.ipvoid.com", data=values, headers=headers)

        # if data is stale, submit update request + re-query for data
        try:
            adate = r.text.split("Analysis Date</td><td>")[1].split("</td>")[0].split(" ")
            if adate[1] in ["month","months"] or adate[1] == "days" and int(adate[0]) >= 2:
                r = requests.get("http://www.ipvoid.com/update-report/" + self.ip)
                r = requests.get("http://www.ipvoid.com/scan/" + self.ip)

            blist = r.text.split("Blacklist Status</td><td>")[1].split("</span>")[0].split("\">")[1].split(" ")
            blist = blist[len(blist) - 1]
            isp = r.text.split("ISP</td><td>")[1].split("</td>")[0]
            asn = r.text.split("ASN Owner</td><td>")[1].split("</td>")[0]
            rdns = r.text.split("Reverse DNS</td><td>")[1].split("</td>")[0]
            cntry = r.text.split('alt="Flag" />')[1].split("</td>")[0].split(")")[1].strip()

            self.blist = blist
            self.isp = isp
            self.asn = asn
            self.rdns = rdns
            self.cntry = cntry
            return True
        except IndexError:
            return False

    def __urlvoid(self):
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36"}
        r = requests.get("http://www.urlvoid.com/ip/" + self.ip, headers=headers)

        if "<h1>Report not found</h1>" in r.text:
            self.urlvoid = {"count": "N/A", "domains": [["N/A"]]}
        else:
            domainc = [0, 0]
            domains = []
            try:
                lst = r.text.split("<tbody>")[1].split("</tbody>")[0].replace("\t", "").split("\n")
                for item in lst:
                    item = item.strip()
                    if item == "":
                        continue
                    elif item[:8] == "<tr><td>":
                        domainc[0] += 1
                        domain = item.split("</a>")[0].split("\">")[1]

                        tmp = item.split(" scanning engines")
                        if not len(tmp) == 1:
                            domainc[1] += 1
                            scanners = tmp[0]
                            scanners = scanners[scanners.rfind("\"") + 1:]
                            domains.append([domain, scanners])
                        else:
                            domains.append([domain, "0"])
                self.urlvoid = {"count": domainc, "domains": domains}
            except:
                self.urlvoid = {"count": "N/A","domains":"N/A"}
        return True

    def __vtotal(self):
        apikey = "bc5eccb5798d8deec923ea6e9db1e6e5431bac061254cdb3b64baa0eed490cd3"
        link = "http://www.virustotal.com/vtapi/v2/ip-address/report?apikey="+apikey+"&ip="+self.ip
        r = requests.get(link)
        #print(r.text)
        if r.text == "":
            domains = ["N/A"]
            urls = ["N/A"]
            domainc = "N/A"
        else:
            resp = json.loads(r.text)
            if resp['response_code'] == 0:
                domains = ["N/A"]
                urls = ["N/A"]
                domainc = "N/A"
            else:
                if self.cntry == "":
                    try:
                        self.cntry = resp['country']
                    except:
                        pass
                try:
                    domains = resp['resolutions']
                except:
                    domains = "N/A"
                domainc = str(len(domains)) if not domains == "N/A" else "N/A"
        self.vtotal = {"domain_count": domainc, "domains": domains}

    def update(self):
        # query IPVoid, URLVoid, VirusTotal
        try:
            self.__ipvoid()
            self.__urlvoid()
            self.__vtotal()
        except:
            pass

def getiocsS(ioc):
    if ioc in ["","http://","www."," "]:
        return False
    elif re.match("((?:[0-9]{1,3}\.){3}[0-9]{1,3})",ioc):
        return IPAddress(ioc)
    else:
        return False
    #elif re.match("^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z0-9][a-z0-9-]{0,61}[a-z0-9]|[a-z]{2,6}\.[a-z]{2})$",ioc):
        #return Domain(ioc)


def getiocsF(files):
    iocs = []
    iocss = []
    for file in files:
        with open(file, 'r',newline='') as f:
            reader = csv.reader(f)
            for row in reader:
                try:
                    col1 = row[0]
                except:
                    continue
                tmp = getiocsS(col1.strip())
                if not tmp:
                    continue
                elif not col1 in iocss:
                    iocs.append(tmp)
                    iocss.append(col1)
                else:
                    continue
        if not iocs:
            print("ERROR: Nothing for for %s, skipping" % (file))
    return iocs

if __name__ == "__main__":
    # argument parsing
    parser = argparse.ArgumentParser()
    parser.add_argument('-i','--input', help="path to file or directory of files (.CSV) to parse (default: input)",default="input")
    parser.add_argument('-o', '--output', dest="output", help="specify output file (default: IOC-Check.html)",
                        default="IOC-Check.html")
    parser.add_argument('-d', '--delay', dest="delay",
                        help="specify the time to wait, in seconds, between each IP check (default: 2 seconds)",
                        type=int, default=2)
    parser.add_argument('-l','--list', action="store_true", help="treat input parameters (-i <input>) as a list of comma separated IOCs")
    args = parser.parse_args()

    if not args.list:
        d = False
        if not isdir(args.input):
            if not isfile(args.input):
                print("ERROR: Provided input is not a file or directory")
                exit(0)
        else:
            if not args.input[-1:] == "\\":
                args.input += "\\"
            d = True

        if d:
            files = [args.input + f for f in listdir(args.input) if
                     isfile(args.input + f) and f[-4:] == ".csv"]
            iocs = getiocsF(files)
        else:
            files = [args.input]
            iocs = getiocsF(files)
    else:
        iocs = [getiocsS(x) if not False else "" for x in list(set(args.input.split(",")))]

    start = timeit.default_timer()
    i = 0
    tot = len(iocs)
    print("# of IOCs: %d" % (tot))
    out = OutputTemplate(args.output)
    ips = [x for x in iocs if isinstance(x,IPAddress)]
    for ip in ips:
        ip.update()
        time.sleep(args.delay)
        i += 1
        if not i == tot:
            if i % 4 == 0:
                print("Working... %d / %d" % (i, tot))
                time.sleep(60)
        out.add_data(ip)
    out.out()
    delta = timeit.default_timer() - start
    print("Done, took %d seconds" % (delta))
