
import os
import cherrypy

#PATH = os.path.abspath(os.path.dirname(__file__))

PATH = 'C:\\Users\\\user\\Documents\\GitHub\\Quick_Daemon\\'
class Root(object): pass

cherrypy.tree.mount(Root(), '/', config={
        '/': {
                'tools.staticdir.on': True,
                'tools.staticdir.dir': PATH,
                'tools.staticdir.index': 'index.html',
            },
    })
cherrypy.server.socket_host = '10.5.3.10'

cherrypy.quickstart()
cherrypy.config.update({'server.socket_port': 80})
