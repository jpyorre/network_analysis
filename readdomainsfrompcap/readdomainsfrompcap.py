import dpkt, datetime

pcapdata = []
hosts = []
with open('posttophishingpage.pcap','rb') as f:
	
	pcap = dpkt.pcap.Reader(f)

	for ts, buf in pcap:
		eth = dpkt.ethernet.Ethernet(buf)
		ip = eth.data
		tcp = ip.data

		dtstring=datetime.datetime.fromtimestamp(ts).strftime('%d-%m-%Y %H:%M:%S:%f') # Convert time to string
		#dt=datetime.datetime.strptime(dtstring,'%d-%m-%Y %H:%M:%S:%f') # Convert string time to datetime
		
		try:
			if len(tcp.data) > 0:
				http = dpkt.http.Request(tcp.data)
				headers = http.headers
				hosts.append(headers['host'])
				dest_ip = socket.inet_ntoa(ip.dst)
				src_ip = socket.inet_ntoa(ip.src)
				dest_host = headers['host']
				uri = http.uri
				useragent = headers['user-agent']
				request = repr(http['body'])
				#data = (dtstring, http.method)
				data = ("{0},{1},{2},{3},{4},{5},{6}".format(dtstring, src_ip, useragent, dest_host, dest_ip, http.method, request))
				pcapdata.append(data)

		except Exception as e:
			# print(e)
			pass

for host in set(hosts):
	print(host)