import os
import allel
import sys

VCFfilePath = sys.argv[1]
def OpenVCFfileAsArray(fpath):
	VariantsArr = allel.vcf_to_recarray(fpath)
	return VariantsArr

VCRfileArr = OpenVCFfileAsArray(VCFfilePath)
lenthOfVCR = len(VCRfileArr)
print("lenthOfVCR", lenthOfVCR)
Segments = ['1','100','10000','100000','1000000',str(lenthOfVCR)]
hashTypes = ['sha256','sha512']
RSAbits = ['1024','2048','3072']
print("Segments", Segments)
print("Segments", hashTypes)
print("Segments", RSAbits)



for seg in Segments:
	command = 'python3 SplitArr.py ' + VCFfilePath + ' ' + seg
	print(command)
	os.system(command)
	for bits in RSAbits:
		if (int(seg) == 1):
			ExperimentResultsFileName = str('resultsSegs'+seg+'Bits'+bits)
			command = 'python3 RSAdoSignatureMultiCores.py ' + bits + ' ' + ExperimentResultsFileName + ' ' + str(2)
			print(command)
			os.system(command)
		elif(int(seg) == 100):
			ExperimentResultsFileName = str('resultsSegs'+seg+'Bits'+bits)
			command = 'python3 RSAdoSignatureMultiCores.py ' + bits + ' ' + ExperimentResultsFileName + ' ' + str(26)
			print(command)
			os.system(command)
		else:
			ExperimentResultsFileName = str('resultsSegs'+seg+'Bits'+bits)
			command = 'python3 RSAdoSignatureMultiCores.py ' + bits + ' ' + ExperimentResultsFileName + ' ' + str(33)
			print(command)
			os.system(command)