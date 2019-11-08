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

This module calculates the probabilities of all information flows.

ARGUMENTS:
---------

-r:     Directory of real information flows (.txt files)
-t:     Directory of total information flows (.txt file)
-o:     Directory of information flows' probabilities (.csv file)

USAGE:
-----

python Probability.py -r '/Directory/of/RealFlows' -t '/Directory/of/TotalFlows' -o '/Directory/of/ProbabilityTable'
'''
# ************************ End of Module Information  ************************

# ************************ Importing Modules ************************

import os
import shutil
import csv
import glob
import operator
import pickle
import sys
from collections import defaultdict

# ************************ End of Importing Modules ************************

# ************************ Initialization ************************

arguments = sys.argv
if '-r' not in arguments or '-t' not in arguments or '-o' not in arguments:
    raise NameError('Error: input options are not provided')
else:
    # Directory of real information flows
    Real_Flows_Dir = arguments[arguments.index('-r') + 1]
    # Directory of total information flows
    Total_Flows_Dir = arguments[arguments.index('-t') + 1]
    # Directory of probability table for all information flows
    Output_Dir = arguments[arguments.index('-o') + 1]

# Directories
Home_Dir = os.path.curdir           # Home directory

Dict_Srcs_Nat = {}                  # Dictionary of SuSi source API methods in natural format
Dict_Snks_Nat = {}                  # Dictionary of SuSi sink API methods in natural format

num_src = 0
with open(os.path.join(Home_Dir,'Sources.txt')) as src_txt:
    for line in src_txt:
        line = line.strip()
        Dict_Srcs_Nat[num_src + 1] = line
        num_src += 1

num_snk = 0
with open(os.path.join(Home_Dir,'Sinks.txt')) as snk_txt:
    for line in snk_txt:
        line = line.strip()
        Dict_Snks_Nat[num_snk + 1] = line
        num_snk += 1

# Creating matrices for storing real info-flows, total info-flows, and their probabilities
Real_InfoFlows_method = defaultdict(int)
Total_InfoFlows_method = defaultdict(int)
Prob_InfoFlows_method = {}

# ********************* End of Initialization *********************

# ********************* Main Body *********************

for file in glob.iglob(os.path.join(Real_Flows_Dir, "*.txt")):

    dirname,filename = os.path.split(file)

    flag_total = defaultdict(int)

    # Counting the total number of sources and sinks within each app by looking through smali files
    total_flows = pickle.load(open(os.path.join(Total_Flows_Dir,filename[:-14]+'-totalflows.txt'),'rb'))

    # Updating the corresponding array based on the total number of sources and sinks in each app
    for i in range(0,len(total_flows)):
        flag_total[(total_flows[i][0], total_flows[i][1])] = 1
        Total_InfoFlows_method[(total_flows[i][0], total_flows[i][1])] += 1

    # Counting the real number of sources and sinks within each app by looking through smali files
    f = open(file,'rb')
    real_flows = pickle.load(f)

    # Updating the corresponding array based on the real number of sources and sinks in each app (Those which have connections)
    for i in range(0,len(real_flows)):
        if flag_total[(real_flows[i][0], real_flows[i][1])] == 1:
            Real_InfoFlows_method[(real_flows[i][0], real_flows[i][1])] += 1

    f.close()
            
# Creating the overall probability matrix for information flows
for key in Real_InfoFlows_method.keys():
    if key in Total_InfoFlows_method.keys() and Total_InfoFlows_method[key] != 0:
        Prob_InfoFlows_method[key] = float(Real_InfoFlows_method[key]) / (Total_InfoFlows_method[key])

# ********************* End of Main Body *********************

# ********************* Storing the results *********************

if not os.path.exists(Output_Dir):
    os.mkdir(Output_Dir)

# ********************* Creating the probability table of Non-Empty information flows *********************

# Creating the headers of rows and columns
with open(os.path.join(Output_Dir,'Prob_InfoFlows.csv'), 'w') as csvfile:
    a = csv.writer(csvfile)
    a.writerow(['Sources']+['Sinks']+['Probability'])
    for key in Prob_InfoFlows_method.keys():
        if Prob_InfoFlows_method[key] != 0:
            pr = str(Prob_InfoFlows_method[key])
            a.writerow([Dict_Srcs_Nat[key[0]]]+[Dict_Snks_Nat[key[1]]]+[pr])

# ****************** End of Creating the probability table of Non-Empty information flows ******************

# ********************* Sorting the probability table of Non-Empty information flows *********************

Unsorted_File =open(os.path.join(Output_Dir,'Prob_InfoFlows.csv'), 'r')
infile = csv.reader(Unsorted_File)
infields = infile.__next__()
index = infields.index('Probability')
Sorted_File = sorted(infile, key=operator.itemgetter(index))
with open(os.path.join(Output_Dir,'Prob_InfoFlows_Sorted.csv'),'w') as csvfile:
    a = csv.writer(csvfile)
    a.writerow(infields)
    for row in Sorted_File:
        a.writerow(row)

# ********************* End of Sorting the probability table of Non-Empty information flows *********************

os.remove(os.path.join(Output_Dir,'Prob_InfoFlows.csv'))     # Removing the unsorted probability table

# ********************* End of Storing the results *********************
