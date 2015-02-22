import zerorpc

client = zerorpc.Client()
url = "tcp://localhost:5555"
client.connect(url)

print client.reverse("alfabeta")
print client.makebig("alfabeta")
