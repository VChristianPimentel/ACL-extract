import pandas as pd
import csv
class Acl_Extractor():
    def __init__(self, file_name):
        self.file_name = file_name
        self.access_list = []
        self.object_dict = {}
    def get_file_name(self):
        return self.file_name
    def set_file_name(self, file_name):
        self.file_name = file_name
    def clear_access_list(self):
        self.access_list.clear()
    def clean_line(self, line):
        line = line.strip().split(' ' , 1)[1]
        if 'host' in line:
            return line.split('host')[1].strip().rstrip('\n')+';'
        elif 'object' in line:
            return line.split('object')[1].strip().rstrip('\n')+';'
        elif 'v4' in line:
            return line.replace('v4', '')+';'
        return line+';'
    def search_dict(self, line):
        final_line = ''
        if line.endswith(';'):
            line = line[:-1]
        objects = line.split(';')
        for item in objects:
            if item in self.object_dict:
                final_line += self.object_dict[item]
            else:
                final_line += item+';'
        return final_line
    def extract_access_list(self):
        with open(self.file_name) as fp:
            line = fp.readline()
            while line:
                if line.startswith('access-list'):
                    self.access_list.append(line)
                if line.startswith('object network'):
                    key = line.split()[2]
                    line = fp.readline()
                    temp = self.clean_line(line)
                    self.object_dict[key] = self.clean_line(line)
                if line.startswith('object-group'):
                    key = line.split()[2]
                    temp = ''
                    line = fp.readline()
                    while(not line.startswith('object-group') and not line.startswith('access-list')):
                        temp += self.clean_line(line)
                        line = fp.readline()
                    self.object_dict[key] = temp
                else:
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
                    if data[5] in self.object_dict:
                        ac_dict['protocol'] = self.search_dict(self.object_dict[data[5]])
                    else:
                        ac_dict['protocol'] = data[5]
                    index = 6
                if data[index] in source_types:
                    index+=1
                    if data[index] in self.object_dict:
                        ac_dict['source'] = self.search_dict(self.object_dict[data[index]])
                    else:
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
                        if data[index] in self.object_dict:
                            ac_dict['destination'] = self.search_dict(self.object_dict[data[index]])
                        else:
                            ac_dict['destination'] = data[index]
                        index+=1
                        if len(data) > index+1:
                            if not data[index] == 'log' and not data[index] == 'time-range':
                                if data[index] in source_types:
                                    if data[index+1] in self.object_dict:
                                        ac_dict['ports'] = self.search_dict(self.object_dict[data[index+1]])
                                    else:
                                        ac_dict['ports'] = data[index+1]
                                else:
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
                                if data[index] in ports or data[index] in source_types:
                                    if data[index] in source_types:
                                        if data[index+1] in self.object_dict:
                                            ac_dict['ports'] = self.search_dict(self.object_dict[data[index+1]])
                                        else:
                                            ac_dict['ports'] = data[index+1]
                                    else:
                                        ac_dict['ports'] = '{} {}'.format(data[index], data[index+1])
                                    break
                                elif data[index] == 'log' or data[index] == 'time-range':
                                    break
                            except IndexError:
                                break
                            temp += data[index]+';'
                            index+=1      
                        if temp:
                            ac_dict['destination'] = temp
                ac_dict['log'] = 'enable' if 'log' not in ac else 'disabled'
                ac_dict['remark'] = remark
                remark = ''
                ac_list.append(ac_dict)
            elif data[2] == 'remark':
                remark += ac.split('remark')[1]
        return pd.DataFrame(ac_list)

    def to_csv(self, dataframe, csv_name):
        try:
            dataframe.to_csv(csv_name)
            return True
        except:
            return False