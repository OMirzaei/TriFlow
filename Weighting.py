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

This module calculates the weights of all real information flows based on their frequencies in malwares and benign applications.

ARGUMENTS:
---------

-i:     Directory of information flows' frequencies (.CSV files) in malwares and benign applications
-o:     Directory of information flows' weights (.csv file)

USAGE:
-----

python Weighting.py -i '/Directory/of/FrequencyTables' -o '/Directory/of/WeightTable'
'''
# ************************ End of Module Information  ************************

# ************************ Importing Modules ************************

import os
import csv
import ast
import math
import collections
import sys

# ************************ End of Importing Modules ************************

# ************************ Initialization ************************

arguments = sys.argv
if '-i' not in arguments  or '-o' not in arguments:
    raise NameError('Error: input options are not provided')
else:
    # Directory of info-flows' frequencies (.CSV files) in malwares and benign applications
    Input_Dir = arguments[arguments.index('-i') + 1]
    # Directory of weight table for all information flows
    Output_Dir = arguments[arguments.index('-o') + 1]

# ************************ End of Initialization ************************

# ********************* Creating dictionaries *********************

# Dictionary of info-flows' frequencies in malwares
Dict_Freq_Mal = {}
# Dictionary of info-flows' frequencies in benign applications
Dict_Freq_Good = {}                                     
Dict_Weights = {}
K = 0
with open(os.path.join(Input_Dir,'Freq_InfoFlows_Malware.csv')) as Freq_Mal:
        reader = csv.reader(Freq_Mal)
        reader.next()
        for row in reader:
            Dict_Freq_Mal[(row[0],row[1])]=row[2]
with open(os.path.join(Input_Dir,'Freq_InfoFlows_Benign.csv')) as Freq_Good:
        reader = csv.reader(Freq_Good)
        reader.next()
        for row in reader:
            Dict_Freq_Good[(row[0],row[1])]=row[2]

# ********************* End of Creating dictionaries *********************

# ********************* Calculating the weights of info-flows *********************

min_value = Dict_Freq_Good[min(Dict_Freq_Good, key=Dict_Freq_Good.get)]     # Minimum frequency value in goodware dataset
K =  math.ceil(-math.log(ast.literal_eval(min_value),2))

for key,value in Dict_Freq_Mal.iteritems():
    if key in Dict_Freq_Good:
        Dict_Weights[key] = -ast.literal_eval(Dict_Freq_Mal[key]) * math.log(ast.literal_eval(Dict_Freq_Good[key]),2)
    else:
        Dict_Weights[key] = ast.literal_eval(Dict_Freq_Mal[key]) * K
for key,value in Dict_Freq_Good.iteritems():
    if key not in Dict_Freq_Mal:
        Dict_Weights[key] = 0

# ********************* End of Calculating the weights of info-flows *********************

Sorted_Dict_Weights = collections.OrderedDict(sorted(Dict_Weights.items(), key=lambda t: float(t[1])))

# ********************* Creating the weight table for all information flows *********************

if not os.path.exists(Output_Dir):
    os.mkdir(Output_Dir)

# Creating the headers
with open(os.path.join(Output_Dir,'Weights_InfoFlows_Sorted.csv'), 'wb') as csvfile:
    a = csv.writer(csvfile)
    a.writerow(['Source']+['Sink']+['Weight'])
    for key,value in Sorted_Dict_Weights.iteritems():
        a.writerow([key[0]]+[key[1]]+[Sorted_Dict_Weights[key]])

# ****************** End of Creating the weight table for all information flows ******************
