import os
import allel
import sys

VCFfilePath = sys.argv[1]

Iteration = ['1','100','1000','10000']



# command = 'python3 SplitArr.py ' + VCFfilePath + ' ' + str(1)
# print(command)
# os.system(command)
	
for Iter in Iteration:
	command = 'python3 SaltedMHTMulti.py ' + Iter
	print(command)
	os.system(command)
