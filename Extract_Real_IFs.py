# ************************ General Information ************************
'''
VERSION:
-------

Version (by release date): 2018-11-21

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

This module extracts real information flows from FlowDroid output files (.txt files).

ARGUMENTS:
---------

-i:     Directory of FlowDroid output files (.txt files)
-o:     Directory of real information flows extracted from FlowDroid output files (The output files are in .txt format as well)

USAGE:
-----

python Extract_Real_IFs.py -i '/Directory/of/FlowDroid/OutputFiles' -o '/Directory/of/RealFlows'
'''
# ************************ End of Module Information  ************************

# ************************ Importing Modules ************************

import os
import shutil
import csv
import glob
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
    # Directory of FlowDroid output files (.txt files)
    Input_Dir = arguments[arguments.index('-i') + 1]
    # Directory of real flows extracted from FlowDroid output files
    Output_Dir = arguments[arguments.index('-o') + 1]

# Directories
Home_Dir = os.path.curdir

# Number of processes
n_procs = 4
# Dictionary of SuSi source API methods in natural format
Dict_Srcs_Nat = {}
# Dictionary of SuSi sink API methods in natural format
Dict_Snks_Nat = {}
# Dictionary of real information flows
Dict_Real_Flows = []

num_src = 0
with open(os.path.join(Home_Dir,'Sources.txt')) as src_txt:
    for line in src_txt:
        line = line.strip()
        Dict_Srcs_Nat[line] = num_src + 1
        num_src += 1

num_src_method = num_src

num_snk = 0
with open(os.path.join(Home_Dir,'Sinks.txt')) as snk_txt:
    for line in snk_txt:
        line = line.strip()
        Dict_Snks_Nat[line] = num_snk + 1
        num_snk += 1

num_snk_method = num_snk

# ********************* End of Initialization *********************

# ********************* Functions *********************

def Extract_RealFlows(appfile):

    global Dict_Real_Flows

    dirname,filename = os.path.split(appfile)
    # A flag to avoid repetitive real flows (Note: The zero index is not used for the sake of facility)
    flag_realflows = [[0 for x in range(num_snk_method+1)] for x in range(num_src_method+1)]
    row_idx = 0
    col_idx = 0

    if filename not in os.listdir(Output_Dir):
        # Opening FlowDroid output file to extract real information flows
        flows_file = open(os.path.join(Input_Dir,filename),'r')
        for line in flows_file:
            if 'Found a flow to sink' in line:
                row_idx = 0
                col_idx = 0
                snk_name = '<' + line.split('<')[1].split('>')[0] + '>'
                if snk_name in Dict_Snks_Nat.keys():
                    col_idx = Dict_Snks_Nat[snk_name]
            if '	-' in line:
                src_name = '<' + line.split('<')[1].split('>')[0] + '>'
                if src_name in Dict_Srcs_Nat.keys():
                    row_idx = Dict_Srcs_Nat[src_name]

            if flag_realflows[row_idx][col_idx] == 0 and row_idx != 0 and col_idx != 0:
                Dict_Real_Flows.append((row_idx,col_idx))
                flag_realflows[row_idx][col_idx] = 1
        flows_file.close()

        result = open(os.path.join(Output_Dir,filename[:-10] + '-realflows.txt'),'wb')
        pickle.dump(Dict_Real_Flows,result)
        result.close()
        Dict_Real_Flows = []

# ********************* End of Functions *********************

# ********************* Main Body *********************

if not os.path.exists(Output_Dir):
    os.mkdir(Output_Dir)

pool = multiprocessing.Pool(n_procs)
results = [pool.apply_async(Extract_RealFlows, [appfile]) for appfile in glob.iglob(os.path.join(Input_Dir, "*.txt"))]
pool.close()
pool.join()

# ********************* End of Main Body *********************
