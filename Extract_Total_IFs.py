# ************************ General Information ************************
'''
VERSION:
-------

Version (by release date): 2019-11-08

DEVELOPER INFORMATION:
---------------------

Name: Omid Mirzaei
Laboratory: Computer Security Lab (COSEC)
University: Universidad Carlos III de Madrid
Website: https://cosec.inf.uc3m.es/~omid-mirzaei/

PUBLICATION:
-----------

TriFlow: Triaging Android Applications using Speculative Information Flows
O. Mirzaei, G. Suarez-Tangil, J. E. Tapiador, J. M. de Fuentes
ACM Asia Conference on Computer and Communications Security (ASIACCS), Abu Dhabi, UAE (April 2017)

COPYRIGHT NOTICE:
----------------

All rights reserved for the above developer and research center.
Please, take a look at the "License.txt" file for more detailed information regarding the usage and distribution of these source codes.

ACKNOWLEDGEMENT:
---------------

This work was supported by the MINECO grant TIN2013-46469-R (SPINY: Security and Privacy in the Internet of You);
by the CAM grant S2013/ICE-3095 (CIBER- DINE: Cybersecurity, Data, and Risks), and
by the MINECO grant TIN2016-79095-C2-2-R (SMOG-DEV - Security Mechanisms for Fog Computing: Advanced Security for Devices)
'''
# ************************ End of General Information ************************

# ************************ Module Information ************************
'''
MAIN FUNCTIONALITY:
------------------

This module extracts total information flows from applications (.apk files).

ARGUMENTS:
---------

-i:     Directory of original applications (.apk files)
-o:     Directory of total information flows extracted from applications (The output files are in .txt format)

USAGE:
-----

python Extract_Total_IFs.py -i '/Directory/of/Applications' -o '/Directory/of/TotalFlows'
'''
# ************************ End of Module Information  ************************

# ************************ Importing Modules ************************

import os
import shutil
import glob
import zipfile
import pickle
import multiprocessing
import re
import sys
from DexParser import DalvikParser

# ************************ End of Importing Modules ************************

# ************************ Initialization ************************

arguments = sys.argv
if '-i' not in arguments  or '-o' not in arguments:
    raise NameError('Error: input options are not provided')
else:
    # Directory of applications (.apk files)
    Input_Dir = arguments[arguments.index('-i') + 1]
    # Directory of total flows extracted from applications
    Output_Dir = arguments[arguments.index('-o') + 1]

# Home directory
Home_Dir = os.path.curdir
# Number of processes
n_procs = 4                                                         
# Dictionary of SuSi source API methods
Dict_Srcs = {}
# Dictionary of SuSi sink API methods
Dict_Snks = {}
# Dictionary of total information flows between all sources and sinks
Dict_Total_Flows = []

Dict_Srcs = {}
num_src = 0
with open(os.path.join(Home_Dir,'Sources_Smali.txt')) as src_txt:
    for line in src_txt:
        line = line.strip()
        class_name = line.split(';->')[0]
        method_name = line.split(';->')[1].split('(')[0]
        output = line.split(';->')[1].split(')')[1]
        params = line.split(';->')[1].split(')')[0]
        params = params.split('(')[1]

        params = params.split(';')
        new_params = ''
        for par in params:
            new_params = new_params + re.sub('L.*', 'L', par)

        key = class_name + ';' + method_name + '(' + new_params +')' + output
        Dict_Srcs[key] = num_src + 1
        num_src += 1                 

num_src_method = num_src

Dict_Snks = {}
num_snk = 0
with open(os.path.join(Home_Dir,'Sinks_Smali.txt')) as snk_txt:
    for line in snk_txt:
        line = line.strip()
        class_name = line.split(';->')[0]
        method_name = line.split(';->')[1].split('(')[0]
        output = line.split(';->')[1].split(')')[1]
        params = line.split(';->')[1].split(')')[0]
        params = params.split('(')[1]

        params = params.split(';')
        new_params = ''
        for par in params:
            new_params = new_params + re.sub('L.*', 'L', par)

        key = class_name + ';' + method_name + '(' + new_params +')' + output
        Dict_Snks[key] = num_snk + 1
        num_snk += 1                 

num_snk_method = num_snk

# ********************* End of Initialization *********************

# ********************* Functions *********************

def Unzip(app):
    # ---------------------- Extracting App's Name ---------------------- 
    app_name = app.split('/')[-1][:-4]
    # ---------------------- End of Extracting App's Name ---------------------- 
    # ---------------------- Removing Smali_Files and Unzipped_App folders if they already exist ---------------------- 
    if app_name in os.listdir(Input_Dir):
        shutil.rmtree(os.path.join(Input_Dir, app_name))
    # ---------------------- End of Removing Smali_Files and Unzipped_App folders if they already exist ---------------------- 
    # ---------------------- Unzipping the application (.apk file) ---------------------- 
    os.mkdir(os.path.join(Input_Dir, app_name))
    with zipfile.ZipFile(app,"r") as zip_ref:
        zip_ref.extractall(os.path.join(Input_Dir, app_name))
    # ---------------------- End of Unzipping the application (.apk file) ---------------------- 
    dex_file_paths = []
    for root, dirs, files in os.walk(os.path.join(Input_Dir, app_name)):
        for file in files:
            if '.dex' in file:
                dex_file_paths.append(os.path.join(root, file))
    
    return dex_file_paths


def Extract_Methods(dex_file):

    List_Methods = set()
    dex = DalvikParser.Dalvik.fromfilename(dex_file)
    for mtd in dex.methods.methods:
        full_method_sig = mtd['class'] + mtd['name'] + '(' + mtd['proto']['name'][1:] + ')' + mtd['proto']['type']
        List_Methods.add(full_method_sig)

    return List_Methods


def Extract_TotalFlows(appfile):

    global Dict_Total_Flows
    # A flag to avoid repetitive sources and sinks found within an application (Note: The zero index is not used for the sake of facility)
    flag_srcs = [0 for x in range(num_src_method + 1)]
    flag_snks = [0 for x in range(num_snk_method + 1)]
    # Two matrices which are used to store total sources and sinks found within an application
    rows_idx_method = [0 for x in range(num_src_method+1)]
    cols_idx_method = [0 for x in range(num_snk_method+1)]

    dirname,filename = os.path.split(appfile)
    methods = set()

    if filename + '-Sources_Results.txt' not in os.listdir(Output_Dir) or filename + '-Sinks_Results.txt' not in os.listdir(Output_Dir):
        # Contains all the sources
        srcs_results = open(os.path.join(Output_Dir,filename + '-Sources_Results.txt'),'wb')
        # Contains all the sinks
        snks_results = open(os.path.join(Output_Dir,filename + '-Sinks_Results.txt'),'wb')

        # ---------------------- Extracting Methods from Dex File ---------------------- 
        dex_file_paths = Unzip(appfile)
        for dex_path in dex_file_paths:
            current_methods = Extract_Methods(dex_path)
            methods = methods | current_methods
        # ---------------------- End of Extracting Methods from Dex File ---------------------- 
        for m in methods:
            if m in Dict_Srcs.keys():
                flag_srcs[Dict_Srcs[m]] = 1
            if m in Dict_Snks.keys():
                flag_snks[Dict_Snks[m]] = 1

        pickle.dump(flag_srcs,srcs_results)
        pickle.dump(flag_snks,snks_results)
        srcs_results.close()
        snks_results.close()

        rows_idx_method = pickle.load(open(os.path.join(Output_Dir,filename + '-Sources_Results.txt'),'rb'))
        cols_idx_method = pickle.load(open(os.path.join(Output_Dir,filename + '-Sinks_Results.txt'),'rb')) 

        # Updating the dictionary based on the total number of sources and sinks in each app
        for i in range(0,num_src_method+1):
            if rows_idx_method[i] == 1:
                for j in range(0,num_snk_method+1):
                    if cols_idx_method[j] == 1:
                        Dict_Total_Flows.append((i, j))

        result = open(os.path.join(Output_Dir,filename + '-totalflows.txt'),'wb')
        pickle.dump(Dict_Total_Flows,result)
        result.close()
        Dict_Total_Flows = []

        shutil.rmtree(os.path.join(Input_Dir,filename[:-4]))
        shutil.move(os.path.join(Output_Dir,filename + '-Sources_Results.txt'),os.path.join(Output_Dir,'Sources',filename + '-Sources_Results.txt'))
        shutil.move(os.path.join(Output_Dir,filename + '-Sinks_Results.txt'),os.path.join(Output_Dir,'Sinks',filename + '-Sinks_Results.txt'))
        shutil.move(os.path.join(Output_Dir,filename + '-totalflows.txt'),os.path.join(Output_Dir,'Flows',filename + '-totalflows.txt'))

    return methods
    
# ********************* End of Functions *********************

# ********************* Main Body *********************

if not os.path.exists(Output_Dir):
    os.mkdir(Output_Dir)
    os.mkdir(os.path.join(Output_Dir,'Sources'))
    os.mkdir(os.path.join(Output_Dir,'Sinks'))
    os.mkdir(os.path.join(Output_Dir,'Flows'))

pool = multiprocessing.Pool(n_procs)
results = [pool.apply_async(Extract_TotalFlows, [appfile]) for appfile in glob.iglob(os.path.join(Input_Dir, "*.apk"))]
pool.close()
pool.join()

# ********************* End of Main Body *********************