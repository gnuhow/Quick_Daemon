import zerorpc

def reverse(text):
    """ return reversed argument """
    return text[::-1]

def makebig(text):
    """ turn text to uppercase letters """
    return text.upper()
    
url = "tcp://*:5555"

srv = zerorpc.Server(worker)
srv.bind(url)
srv.run()
