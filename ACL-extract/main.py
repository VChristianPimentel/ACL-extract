import sys
from acl_extractor import Acl_Extractor
if __name__ == "__main__":
    again = True
    while(again):
        try:
            file = input('File to proccess:')
            file = './files/file2'
            csv_filename = file+'.csv'
            extractor = Acl_Extractor(file)
            extractor.extract_access_list()
            panda = extractor.create_panda()
            if(extractor.to_csv(panda, csv_filename)):
                print('Csv successfully created at:',csv_filename)
            else:
                print('An error ocurred in the csv creation.')
            if(input('Again?: True|False') == False):
                sys.exit()
        except KeyboardInterrupt:
            print('Goodbye!')