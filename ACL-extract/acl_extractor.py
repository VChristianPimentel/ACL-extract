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
        protocols = ['ip','udp','tcp','icmp']
        source_types = ['object-group','object','host']
        ports = ['eq']
        especial = False
        remark = ''
        for ac in self.access_list:
            ac_dict = {}
            index = 0
            data = ac.split()
            if(data[2] == 'extended'):
                ac_dict['acl-name'] = data[1]
                ac_dict['action'] = data[3]
                if data[4] in protocols:
                    ac_dict['protocol'] = data[4]
                    index = 5
                else:
                    ac_dict['protocol'] = data[5]
                    index = 6
                if data[index] in source_types:
                    index+=1
                    ac_dict['source'] = data[index]
                    index+=1
                else:
                    temp = ''
                    for index1, sources in enumerate(data, start = index):
                        if data[index] == 'any':
                            ac_dict['source'] = 'any'
                            index+=1
                            break
                        if data[index] == 'any4':
                            ac_dict['source'] = 'any4'
                            index+=1
                            break
                        temp += data[index]
                        index+=1
                        try:
                            if data[index] in source_types or data[index] == 'any':
                                ac_dict['source'] = temp
                                break
                        except:
                            ac_dict['source'] = temp
                            especial = True
                            break
                if not especial:
                    if data[index] in source_types:
                        index+=1
                        ac_dict['destination'] = data[index]
                        index+=1
                        if len(data) > index+1:
                            ac_dict['ports'] = '{} {}'.format(data[index], data[index+1])
                    else:
                        temp = ''
                        if data[index] == 'any':
                                ac_dict['destination'] = 'any'
                                index+=1
                        elif data[index] == 'any4':
                                ac_dict['destination'] = 'any4'
                                index+=1
                        for index2, destination in enumerate(data, start = index):
                            try:
                                if data[index] in ports:
                                    ac_dict['ports'] = '{} {}'.format(data[index], data[index+1])
                                    break
                            except IndexError:
                                break
                            temp += data[index]
                            index+=1      
                        ac_dict['destination'] = temp
                ac_dict['log'] = 'enable' if 'log' not in ac else 'disabled'
                ac_dict['remark'] = remark
                remark = ''
                ac_list.append(ac_dict)
            elif data[2] == 'remark':
                remark += ac.split('remark')[1]
        return pd.DataFrame(ac_list)

    def to_csv(self, dataframe, csv_name):
        # try:
        dataframe.to_csv(csv_name)
        return True
        # except:
        #     return False