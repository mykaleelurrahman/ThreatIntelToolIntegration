# Recommendation systems using Python
import re
domains = ["www.toptrust.com", "www.tamarind.com", "www.helloworld.in","optrustooo.ooo"]

d_matched = []
for i in domains:
    if re.search('trust', i, re.IGNORECASE):
        d_matched.append(i)

print(d_matched)

