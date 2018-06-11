import graphviz as gv
from hashlib import md5
import os


class Formatter():

    class Node():
        def __init__(self, *args, **kwargs): pass

    class ProcessNode(Node): pass

    class FileNode(Node): pass

    class NetworkNode(Node): pass

    class RegistryNode(Node): pass

    class ResourceNode(Node): pass

    class ServiceNode(Node): pass

    class CryptoNode(Node): pass

    def __init__(self, *args, **kwargs): pass

    def operation(self, *args, **kwargs): pass

    def update(self, *args, **kwargs): pass


class GraphViewer(Formatter):

    _graph_style_ = {
        # 'label':'Fancy graph',
        'fontsize': '16',
        'fontcolor': 'grey',
        'bgcolor': 'white',
        'rankdir': 'TB',
        'labeljust': 'l',
    }

    class Node():

        _styles_ = None

        @property
        def node_style(self):
            if 'Node' not in self._styles_: return {}
            return self._styles_['Node']

        @node_style.setter
        def node_style(self, value):
            self._styles_['Node'] = value

        @property
        def edge_style(self):
            if 'Edge' not in self._styles_: return {}
            return self._styles_['Edge']

        @edge_style.setter
        def edge_style(self, value):
            self._styles_['Edge'] = value

        @property
        def name(self):
            return self._name

        @name.setter
        def name(self, value):
            self._name = md5(str(value).encode('utf8')).hexdigest()

        @property
        def label(self):
            return self._label

        @label.setter
        def label(self, value):
            if isinstance(value, bytes):
                try: value = value.decode('utf8')
                except: pass
            escaped = str(value)
            for c, r in [('\r\n', '\l'), ('\\', '/')]:
                escaped = escaped.replace(c, r)
            self._label = escaped

        def __init__(self, name, label=None, styles={}):
            self.name = name

            if label is not None: self.label = label
            else: self.label = name

            if not self._styles_ or styles: self._styles_ = styles

    class ProcessNode(Node):

        _styles_ = {
            'Node': {

                'shape': 'hexagon',
                'style': 'rounded, filled',
                'fillcolor': 'lightblue',
            },

            'Edge': {
                'style': 'solid',
                'fillcolor': 'lightblue',
            }
        }

    class FileNode(Node):

        _styles_ = {

            'Node': {
                'shape': 'box',
                'style': 'rounded, filled',
                'fillcolor': '#CCCCFF',
            },

            'Edge': {
                'style': 'solid',
                'fillcolor': '#CCCCFF',
            }
        }

    class ServiceNode(Node):

        _styles_ = {
            'Node': {
                'shape': 'polygon',
                'style': 'rounded, filled',
                'sides': '4',
                'skew': '.7',
                'fillcolor': '#FFFFCC',
            },

            'Edge': {
                'style': 'dashed',
                'fillcolor': '#FFFFCC',
            }
        }

    class ResourceNode(Node):

        _styles_ = {
            'Node': {
                'shape': 'octagon',
                'style': 'filled',
                'fillcolor': '#FFB266',
            },

            'Edge': {
                'style': 'dashed',
                'fillcolor': '#FFB266',
            }
        }

    class CryptoNode(Node):

        _styles_ = {
            'Node': {
                'shape': 'invhouse',
                'style': 'filled',
                'fillcolor': '#FF9999',
            },

            'Edge': {
                'style': 'solid',
                'fillcolor': '#FF9999',
            }
        }

    class RegistryNode(Node):

        _styles_ = {
            'Node': {
                'shape': 'box',
                'style': 'rounded, filled',
                'fillcolor': '#EEFFEE',
            },

            'Edge': {
                'style': 'solid',
                'fillcolor': '#EEFFEE',
            }
        }

    class NetworkNode(Node):

        _styles_ = {
            'Node': {
                'shape': 'box',
                'style': 'rounded, filled',
                'fillcolor': '#4B4B4B',
                'fontcolor': 'white',
            },
            'Edge': {
                'style': 'dashed',
                'fillcolor': '#4B4B4B',
            }
        }

    def __init__(self, filename, format, style={}, realtime=True):

        self.graph = gv.Digraph(format=format)
        self.filename = filename
        self.format = format
        self.realtime = realtime
        self._cache_nodes = []
        self._cache_operations = {}

        self.__produce_html__()

        self.graph.graph_attr.update(style)

    def __produce_html__(self):

        filename = os.path.split(self.filename)[-1]

        html_content = '''
    <html>
    <head><meta charset="utf-8" http-equiv="refresh" content="3; {}.html"></head>
    <img src="{}.{}">
    </html>
    '''.format(filename, filename, self.format)

        open("%s.html" % self.filename, 'w').write(html_content)
        return

    def __operation_core__(self, node1, node2, label, update_node=False):

        if node1.name not in self._cache_nodes:
            if update_node: return

            self.graph.node(node1.name, label=node1.label, **node1.node_style)
            self._cache_nodes.append(node1.name)

        if node2.name not in self._cache_nodes:
            self.graph.node(node2.name, label=node2.label, **node2.node_style)
            self._cache_nodes.append(node2.name)

        if (node1.name, node2.name, label) not in self._cache_operations:
            self.graph.edge(node1.name, node2.name, label=label, **node1.edge_style)
            self._cache_operations[(node1.name, node2.name, label)] = None

            if self.realtime: self.view()

    def edge(self, node1, node2, action='', style=None):
        return self.__operation_core__(node1, node2, action, False)

    def update(self, node1, node2, action, **kwargs):
        return self.__operation_core__(node1, node2, action, True)

    def view(self):
        self.graph.render(filename=self.filename)
