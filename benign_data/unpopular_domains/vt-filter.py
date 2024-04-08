import sys
import json
import os

if len(sys.argv) < 2:
	print(sys.argv[0] + "virustotal_data output")
	
	
output = open(sys.argv[2], "w+")
count = 0
for filename in os.listdir(sys.argv[1]):
	path = os.path.join(sys.argv[1], filename)
	try:
		vt_data = json.load(open(path))
		if vt_data["data"]["attributes"]["last_analysis_stats"]["malicious"] < 1:
			string = ".".join(filename.split(".")[:-1])
			output.write(string + "\n")
			count += 1
	except:
		print("failed to open " + path)
		pass

output.close()
print("Number of Impact domains after VirusTotal filtering: ", count)