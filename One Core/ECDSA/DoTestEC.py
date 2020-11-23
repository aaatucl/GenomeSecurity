import os
import allel


def OpenVCFfileAsArray(fpath):
	VariantsArr = allel.vcf_to_recarray(fpath)
	return VariantsArr

VCRfileArr = OpenVCFfileAsArray('../../files/NB72462M.vcf')
lenthOfVCR = len(VCRfileArr)
print("lenthOfVCR", lenthOfVCR)
Segments = ['1','100','10000','100000','1000000',str(lenthOfVCR)]
hashTypes = ['sha256']
#RSAbits = ['1024','2048','3027']
print("Segments", Segments)
print("Segments", hashTypes)
#print("Segments", RSAbits)



for y in hashTypes:
	print(y)
	for z in Segments:
		print(z)
		VCFfilePath = '../../files/NB72462M.vcf'
		#print(VCFfilePath)
		SigsFileName = str('EC2withkinv_rp714'+y+'seg'+z+'sigs')
		HashType = y
		Segs = z
		ExperimentResultsFileName = str('EC2withkinv_rp714'+y+'seg'+z+'Time')
		command = '/usr/local/opt/python@3.8/bin/python3 ECDSA.py '+ VCFfilePath+ ' ' + SigsFileName + ' ' + HashType  + ' ' + Segs + ' ' + ExperimentResultsFileName
		print(command)
		os.system(command)
