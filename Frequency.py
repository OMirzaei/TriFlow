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

This module calculates the frequencies of all real information flows.

ARGUMENTS:
---------

-i:     Directory of real information flows (.txt files)
-o:     Directory of information flows' frequencies (.csv file)

USAGE:
-----

python Frequency.py -i '/Directory/of/RealFlows' -o '/Directory/of/FrequencyTable'
'''
# ************************ End of Module Information  ************************

# ************************ Importing Modules ************************

import os
import shutil
import csv
import glob
import math
import operator
import pickle
import sys
from collections import defaultdict

# ************************ End of Importing Modules ************************

# ************************ Initialization ************************

arguments = sys.argv
if '-i' not in arguments  or '-o' not in arguments:
    raise NameError('Error: input options are not provided')
else:
    # Directory of real information flows
    Input_Dir = arguments[arguments.index('-i') + 1]
    # Directory of frequency table for all information flows
    Output_Dir = arguments[arguments.index('-o') + 1]

Home_Dir = os.path.curdir       # Home directory

Num_Apps = 0                    # Total number of apps from which FlowDroid was able to extract any information flows

Dict_Srcs_Nat = {}              # Dictionary of SuSi source API methods in natural format
Dict_Snks_Nat = {}              # Dictionary of SuSi sink API methods in natural format

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

# Creating matrices for storing real information flows and their frequencies (Note: The zero index is not used for the sake of facility)
Real_InfoFlows_method = defaultdict(int)
Freq_InfoFlows_method = {}

# ********************* End of Initialization *********************

# ********************* Main Body *********************

for file in glob.iglob(os.path.join(Input_Dir, "*.txt")):

    dirname,filename = os.path.split(file)

    # Reading real information flows extracted from FlowDroid output files
    f = open(file,'rb')
    real_flows = pickle.load(f)

    if real_flows:
        Num_Apps += 1

    # Updating the corresponding array based on the real number of sources and sinks in each app (Those which have connections)
    for i in range(0,len(real_flows)):
        Real_InfoFlows_method[(real_flows[i][0], real_flows[i][1])] += 1
    
    f.close()


# Creating the overall frequency matrix for information flows
for key in Real_InfoFlows_method.iterkeys():
    if Real_InfoFlows_method[key] != 0:
        Freq_InfoFlows_method[key] = float(Real_InfoFlows_method[key]) / Num_Apps

# ********************* End of Main Body *********************

# ********************* Storing the results *********************

if not os.path.exists(Output_Dir):
    os.mkdir(Output_Dir)

# ********************* Creating the frequency table of Non-Empty information flows for methods *********************

# Creating the headers of rows and columns
with open(os.path.join(Output_Dir,'Freq_InfoFlows.csv'), 'wb') as csvfile:
    a = csv.writer(csvfile)
    a.writerow(['Sources']+['Sinks']+['Frequency'])
    for key in Freq_InfoFlows_method.iterkeys():
        if Freq_InfoFlows_method[key] != 0:
            fr = str(Freq_InfoFlows_method[key])
            a.writerow([Dict_Srcs_Nat[key[0]]]+[Dict_Snks_Nat[key[1]]]+[fr])

# ****************** End of Creating the frequency table of Non-Empty information flows for methods ******************

# ********************* Sorting the frequency table of Non-Empty information flows for methods *********************

Unsorted_File =open(os.path.join(Output_Dir,'Freq_InfoFlows.csv'), 'rb')
infile = csv.reader(Unsorted_File)
infields = infile.next()
index = infields.index('Frequency')
Sorted_File = sorted(infile, key=operator.itemgetter(index))
with open(os.path.join(Output_Dir,'Freq_InfoFlows_Sorted.csv'),'wb') as csvfile:
    a = csv.writer(csvfile)
    a.writerow(infields)
    for row in Sorted_File:
        a.writerow(row)

# ********************* End of Sorting the frequency table of Non-Empty information flows for methods *********************

os.remove(os.path.join(Output_Dir,'Freq_InfoFlows.csv'))     #Removing the unsorted frequency table

# ********************* End of Storing the results *********************
