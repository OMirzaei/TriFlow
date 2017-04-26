# ************************ General Information ************************
'''
VERSION:
-------

Version (by release date): 2017-04-26

DEVELOPER INFORMATION:
---------------------

Name: Omid Mirzaei
Laboratory: Computer Security Lab (COSEC)
University: Universidad Carlos III de Madrid
Website: http://www.seg.inf.uc3m.es/~omirzaei/

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
import subprocess
import pickle
import time
import multiprocessing
import sys

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
# Location of dexdump
dexdump_Loc = Home_Dir + '/dexdump'

# Number of processes
n_procs = 4
# Dictionary of SuSi source API methods
Dict_Srcs = {}
# Dictionary of SuSi sink API methods
Dict_Snks = {}
# Dictionary of total information flows between all sources and sinks
Dict_Total_Flows = []

num_src = 0
with open(os.path.join(Home_Dir,'Sources_DexCode.txt')) as src_txt:
    for line in src_txt:
        line = line.strip()
        line = line.replace('->','.')
        line = line.replace('(',':(')
        Dict_Srcs[line] = num_src + 1
        num_src += 1

num_src_method = num_src

num_snk = 0
with open(os.path.join(Home_Dir,'Sinks_DexCode.txt')) as snk_txt:
    for line in snk_txt:
        line = line.strip()
        line = line.replace('->','.')
        line = line.replace('(',':(')
        Dict_Snks[line] = num_snk + 1
        num_snk += 1

num_snk_method = num_snk

# ********************* End of Initialization *********************

# ********************* Functions *********************

def DisAssemble_Dex(app):
    # ********************** Extracting App's Name **********************
    app_name = app.split('/')[-1][:-4]
    # ********************** End of Extracting App's Name **********************
    # ********************** Removing Smali_Files and Unzipped_App folders if they already exist **********************
    if app_name in os.listdir(Input_Dir):
        shutil.rmtree(os.path.join(Input_Dir,app_name))
    # ********************** End of Removing Smali_Files and Unzipped_App folders if they already exist **********************
    # ********************** Unzipping the application (.apk file) **********************
    os.mkdir(os.path.join(Input_Dir,app_name))
    with zipfile.ZipFile(app,"r") as zip_ref:
        zip_ref.extractall(os.path.join(Input_Dir,app_name))
    # ********************** End of Unzipping the application (.apk file) **********************
    # ********************** Disassembling the classes.dex file within the unzipped folder using dexdump **********************
    dex_file = open(os.path.join(Input_Dir,app_name,app_name + '.txt'),'wb')
    subprocess.call([os.path.join(dexdump_Loc,'dexdump'), '-d', os.path.join(Input_Dir,app_name,'classes.dex')], stdout=dex_file)
    # ********************** End of Disassembling the classes.dex file within the unzipped folder **********************


def Extract_TotalFlows(appfile):

    global Dict_Total_Flows
    # A flag to avoid repetitive sources and sinks found within an application (Note: The zero index is not used for the sake of facility)
    flag_srcs = [0 for x in range(num_src_method + 1)]
    flag_snks = [0 for x in range(num_snk_method + 1)]
    # Two matrices which are used to store total sources and sinks found within an application
    rows_idx_method = [0 for x in range(num_src_method+1)]
    cols_idx_method = [0 for x in range(num_snk_method+1)]

    dirname,filename = os.path.split(appfile)

    if filename + '-Sources_Results.txt' not in os.listdir(Output_Dir) or filename + '-Sinks_Results.txt' not in os.listdir(Output_Dir):
        # Contains all the sources
        srcs_results = open(os.path.join(Output_Dir,filename + '-Sources_Results.txt'),'wb')
        # Contains all the sinks
        snks_results = open(os.path.join(Output_Dir,filename + '-Sinks_Results.txt'),'wb')

        DisAssemble_Dex(appfile)
        # Opening the diassembled .dex file
        dex_file = open(os.path.join(Input_Dir, filename[:-4], filename[:-4] + '.txt'),'rb')
        for line in dex_file:
            if ';.' in line:
                line = line.split(' ')
                API_Method = [i for i in line if (';.' in i)][0]
                if API_Method in Dict_Srcs.iterkeys() and flag_srcs[Dict_Srcs[API_Method]] == 0:
                        flag_srcs[Dict_Srcs[API_Method]] = 1
                if API_Method in Dict_Snks.iterkeys() and flag_snks[Dict_Snks[API_Method]] == 0:
                        flag_snks[Dict_Snks[API_Method]] = 1

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
