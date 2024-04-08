import requests
import re
from urllib.parse import urlparse
import string
import random

states = list(x.lower() for x in [ 'AK', 'AL', 'AR', 'AZ', 'CA', 'CO', 'CT', 'DC', 'DE', 'FL', 'GA',
           'HI', 'IA', 'ID', 'IL', 'IN', 'KS', 'KY', 'LA', 'MA', 'MD', 'ME',
           'MI', 'MN', 'MO', 'MS', 'MT', 'NC', 'ND', 'NE', 'NH', 'NJ', 'NM',
           'NV', 'NY', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC', 'SD', 'TN', 'TX',
           'UT', 'VA', 'VT', 'WA', 'WI', 'WV', 'WY'])

cat_text = requests.get("https://www.yellowpages.com/anchorage-ak").text
categories = set(x for x in re.findall(r'<a href="/anchorage-ak/([^"]+)', cat_text[cat_text.index("Additional Categories"):]))

d_file = open("yp-domains", "w+")

f = open("cities", "a+")
visited_cities = set(open("cities").read().splitlines())
states.reverse()
for state in states:
	r = requests.get(f"https://www.yellowpages.com/state-{state}")
	if r.text == "" or r.status_code != 200:
		break
	r = r.text
	# print(r)
	# <li><a href="/abbeville-ga">
	cities = re.findall(r'<a href="/(\w+-\w+)" data-analytics', r)
	for city in cities:
		if city in visited_cities:
			continue	
		f.write(city + "\n")
		for cat in categories:
			print(cat)
			r = requests.get(f"https://www.yellowpages.com/{city}/{cat}").text
			# print(f"https://www.yellowpages.com/{city}-{state}/{cat}")
			# <a class="track-visit-website" href="https://www.wheatonworldwide.com/get-an-estimate/ballpark-estimate/?utm_source=YP.com&amp;utm_medium=listing&amp;utm_campaign=geminibuy"
			new_domains = set(urlparse(x).netloc for x in re.findall(r'<a class="track-visit-website" href="([^"]+)', r))
			d_file.write("\n".join(new_domains) + "\n")
			# break