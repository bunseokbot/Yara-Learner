from html.parser import HTMLParser


class YLParser(HTMLParser):
    """ Yara Learner target HTML struct parser """
    def initialize(self):
        """ initialize the parser """
        self.data = []

    def handle_starttag(self, tag, attrs):
        """ handle only the src tag to set as communicate """
        for key, value in attrs:
            value = value.replace('\r', '').replace('about:blank', '')\
                         .replace('\n', '')
            if key == "src" and len(value) != 0:
                self.data.append(value)

    def handle_data(self, data):
        """ handle only the data, not the tag and attrs """
        data = data.replace('\r', '').replace('\n', '')
        if len(data) != 0:
            self.data.append(data)
