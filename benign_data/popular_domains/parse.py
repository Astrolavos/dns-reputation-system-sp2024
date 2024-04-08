# https://tranco-list.eu/daily_list\?date\=2021-09-05
# https://tranco-list.eu/download/6JKYX/1000000

from datetime import date, timedelta
import sys
import requests
from multiprocessing import Pool

def daterange(start_date, end_date):
    for n in range(int((end_date - start_date).days)):
        yield start_date + timedelta(n)

start_date = list(int(x) for x in sys.argv[1].split("-"))
end_date = list(int(x) for x in sys.argv[2].split("-"))
start_date = date(start_date[0], start_date[1], start_date[2]) # 2022-12-31
end_date = date(end_date[0], end_date[1], end_date[2]) # 2022-12-31

consistent_set = set()
placement_dict = dict()
for date in daterange(start_date, end_date):
    data = open("tranco/sld_1m/" + date.strftime("%Y-%m-%d")).read().split("\n")[:-1][:int(sys.argv[3])]
    data = list(x.split(",")[1] for x in data)
    if date == start_date:
        consistent_set = set(data)
    else:
        consistent_set = consistent_set.intersection(set(data))
    for i, datum in enumerate(data):
        if datum in consistent_set:
            if datum in placement_dict:
                placement_dict[datum] = min(placement_dict[datum], i)
            else:
                placement_dict[datum] = i

for datum in consistent_set:
    print(str(datum))
