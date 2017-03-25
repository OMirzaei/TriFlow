# ************************ General Information ************************
'''
VERSION:
-------

Version (by release date): 2017-02-15

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
ACM Asia Conference on Computer and Communications Security (ASIACCS), Abu Dhabi, UAE (May 2017)

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
import sys

# ************************ End of Importing Modules ************************

# ************************ Initialization ************************

arguments = sys.argv
if '-i' not in arguments  or '-o' not in arguments:
    raise NameError('Error: input options are not provided')
else:
    # Directory of applications (.apk files)
    Input_Dir = arguments[arguments.index('-i') + 1]
    # Directory of total flows extracted from each application
    Output_Dir = arguments[arguments.index('-o') + 1]

# Home directory
Home_Dir = os.path.curdir
# Directory of total sources and sinks extracted from each application
Total_SrcsSnks_Loc = Home_Dir + '/Total_Srcs_Snks'

global rows_idx_method
global cols_idx_method

Dict_Result = []

# ********************* End of Initialization *********************

# ************************ Creating the Super Set ************************

# Counting the total number of sources
with open(os.path.join(Home_Dir,"Sources_Smali.txt")) as myfile:
    num_src_method = sum(1 for line in myfile)
# Counting the total number of sinks
with open(os.path.join(Home_Dir,"Sinks_Smali.txt")) as myfile:
    num_snk_method = sum(1 for line in myfile)

# ********************* End of Creating the Super Set *********************

# ********************* Main Body *********************

if not os.path.exists(Output_Dir):
    os.mkdir(Output_Dir)

# Extracts total sources and sinks from applications
subprocess.call([sys.executable, os.path.join(Home_Dir,'Extract_Total_SrcsSnks.py'), '-i', Input_Dir, '-o', Total_SrcsSnks_Loc])

for file in glob.iglob(os.path.join(Input_Dir, "*.apk")):

    dirname,filename = os.path.split(file)
    # Contains all the sources which are found from the smali codes of an application
    rows_idx_method = [0 for x in range(num_src_method+1)]
    # Contains all the sinks which are found from the smali codes of an application
    cols_idx_method = [0 for x in range(num_snk_method+1)]

    if filename + '-Sources_Results.txt' in os.listdir(Total_SrcsSnks_Loc) and filename + '-Sinks_Results.txt' in os.listdir(Total_SrcsSnks_Loc) and filename + '-totalflows.txt' not in os.listdir(Output_Dir):
        # Reading pre-computed files which contian all sources and sinks
        rows_idx_method = pickle.load(open(os.path.join(Total_SrcsSnks_Loc,filename + '-Sources_Results.txt'),'rb'))
        cols_idx_method = pickle.load(open(os.path.join(Total_SrcsSnks_Loc,filename + '-Sinks_Results.txt'),'rb'))

        # Creating a set of all possible info-flows
        for i in range(0,num_src_method+1):
            if rows_idx_method[i] == 1:
                for j in range(0,num_snk_method+1):
                    if cols_idx_method[j] == 1:
                        Dict_Result.append((i,j))

        result = open(os.path.join(Output_Dir,filename + '-totalflows.txt'),'wb')
        pickle.dump(Dict_Result,result)
        result.close()
        Dict_Result = []

shutil.rmtree(Total_SrcsSnks_Loc)

# ********************* End of Main Body *********************
