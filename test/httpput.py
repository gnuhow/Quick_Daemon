import  BaseHTTPServer

server_class=BaseHTTPServer.HTTPServer
handler_class=BaseHTTPServer.BaseHTTPRequestHandler
httpd = server_class(('10.5.3.10',80), handler_class)
httpd.serve_forever()

