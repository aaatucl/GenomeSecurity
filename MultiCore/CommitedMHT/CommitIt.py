import numpy as np
import os
#from fastpbkdf2 import pbkdf2_hmac
import hashlib
from hashlib import sha512
from hashlib import sha256

import hmac
from Crypto import *
from Crypto import Random
from Crypto import Util as Cutil






def SaveArr(fname, SegArr):
	file = open(fname, "wb")
	return np.save(file, SegArr)

def OpenArr(fname):
	file = open(fname, "rb")
	return np.load(file, allow_pickle = True)

def CommitThem(pos):
	print("pos: ",pos)
	v = verifier()
	p = prover()
	commitments = [[],[]]
	ArrName = "Arr"+str(pos)
	lvs = OpenArr(ArrName)
	print("Done Loading lvs")
	param = OpenArr('param')
	#print("param: ",param)
	for x in lvs:
		c_hash = sha256((x.encode())).hexdigest()
		c1, r1 = p.commit(param, int(c_hash,16))
		#print(c1, r1)
		commitments[0].append(str(c1))
		commitments[1].append(str(r1))

	CmtName = "commitments" + str(pos)
	print("Size of lvs", len(commitments))
	SaveArr(CmtName,commitments)




def generate(param):
        q = param[1]
        g = param[2]
        h = param[3]
        return q,g,h

class verifier:
    def setup(self, security):
        p = Cutil.number.getPrime(security, Random.new().read)
        q = Cutil.number.getPrime(160, Random.new().read)


        g = Cutil.number.getRandomRange(1, q-1)
        s = Cutil.number.getRandomRange(1, q-1)
        print("Secret value:\t",s)
        h = pow(g,s,q)
        
        param = (p,q,g,h)
        print("p=",p)
        print("q=",q)
        print("g=",g)
        print("h=",h)

        return param

    def open(self, param, c, x, *r):
        result = "False"
        q,g,h = generate(param)

        sum = 0
        for i in r:
            sum += i

        res = (pow(g,x,q) * pow(h,sum,q)) % q

        if(c == res):
            result = "True"
        return result  

    def add(self, param, *cm):
        addCM = 1
        for x in cm:
            addCM *= x
        addCM = addCM % param[1]
        return addCM
        
class prover: 
    def commit(self, param, x):
        q,g,h = generate(param)
        
        r = Cutil.number.getRandomRange(1, q-1)
        c = (pow(g,x,q) * pow(h,r,q)) % q
        return c, r


