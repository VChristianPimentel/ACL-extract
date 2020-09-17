import pandas as pd

class Acl_Extractor():
    def __init__(self, file_name):
        self.file_name = file_name
        self.access_list = []
    def get_file_name(self):
        return self.file_name
    def set_file_name(self, file_name):
        self.file_name = file_name
    def clear_access_list(self):
        self.access_list.clear()
    def extract_access_list(self):
        with open(self.file_name) as fp:
            line = fp.readline()
            while line:
                if line.startswith('access-list'):
                    self.access_list.append(line)
                line = fp.readline()
    def create_panda(self):
        ac_list = []
        protocols = ['ip','udp','tcp']
        source_types = ['object-group','object','host',]
        remark = ''
        for ac in self.access_list:
            ac_dict = {}
            data = ac.split(' ')
            if(data[2] == 'extended'):
                ac_dict['acl-name'] = data[1]
                ac_dict['action'] = data[3]
                # if data[4] in protocols:
                #     ac_dict['protocol'] = data[4]
                #     if data[5] in source_types:
                #         ac_dict['source'] = data[6]
                #     else:
                #         for index,sources in enumerate(ac, start = 5)
                #             if(sources not in source_types)
                #                 ac_dict['source'] += sources
                #             else:
                #                 data
                #                 for index2,sources in enumerate(ac, start = index+1)
                #                     if(sources not in source_types)
                #                     ac_dict['source'] += sources
                # else:
                #     ac_dict['protocol'] = 'any'
                # ac_dict['source'] = data[5]+data[6]
                # ac_dict['destination'] = data[7]+data[8]
                ac_dict['log'] = 'enable' if 'log' not in ac else 'disabled'
                ac_dict['remark'] = remark
                remark = ''
                ac_list.append(ac_dict)
            else:
                remark += data[3]
        return pd.DataFrame(ac_list)

    def to_csv(self, dataframe, csv_name):
        try:
            dataframe.to_csv(csv_name)
            return True
        except:
            return False