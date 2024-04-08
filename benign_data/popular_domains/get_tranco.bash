#!/bin/bash

for day in {07..21}; do
    LIST_ID=$(curl "https://tranco-list.eu/api/lists/date/2023-10-$day" | jq -r .list_id)
    curl -o tranco/sld_1m/2023-10-$day.csv https://tranco-list.eu/download/$LIST_ID/1000000
    curl -o tranco/sld_full/2023-10-$day.csv https://tranco-list.eu/download/$LIST_ID/full
    # break
done


for day in {07..21}; do
    LIST_ID=$(curl "https://tranco-list.eu/api/lists/date/2023-10-$day?subdomains=true" | jq -r .list_id)
    curl -o tranco/subdomain_1m/2023-10-$day.csv https://tranco-list.eu/download/$LIST_ID/1000000
    curl -o tranco/subdomain_full/2023-10-$day.csv https://tranco-list.eu/download/$LIST_ID/full
done
