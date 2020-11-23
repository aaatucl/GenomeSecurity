import numpy as np
import os
#from fastpbkdf2 import pbkdf2_hmac
import hashlib






def SaveArr(fname, SegArr):
	file = open(fname, "wb")
	return np.save(file, SegArr)

def OpenArr(fname):
	file = open(fname, "rb")
	return np.load(file, allow_pickle = True)

def SaltAndIterate(pos,Iter):
	salts = []
	tmplvs = []
	ArrName = "Arr"+str(pos)
	lvs = OpenArr(ArrName)
	for x in lvs:
		#print(x)
		salt = os.urandom(32)
		w = hashlib.pbkdf2_hmac('sha256', x.encode(), salt, Iter)
		w = w.hex()
		tmplvs.append(w)
		salts.append(salt)
	lvsName = "lvs" + str(pos)
	print("Size of lvs", len(tmplvs))
	SaveArr(lvsName,tmplvs)
	SaltsName = "salts" + str(pos)
	print("Size of salts", len(salts))
	SaveArr(SaltsName,salts)






