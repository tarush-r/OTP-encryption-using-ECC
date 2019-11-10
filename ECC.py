arr=[(1,1),(1,2),(1,3),(2,4),(2,5),(2,6),(3,7),(4,8),(4,9),(5,0)]
def map(i,arr):
  switcher={
          0: arr[0],
          1: arr[1],
          2: arr[2],
          3: arr[3],
          4: arr[4],
          5: arr[5],
          6: arr[6],
          7: arr[7],
          8: arr[8],
          9: arr[9],
          0: arr[0]
       }
  return switcher.get(i,(0,0))
def otp(message):
  mapper=[]
  x=10000
  for i in range(5):
    mapper.append(map(int(message/x),arr))
    message = int(message%x)
    x=x/10
  return mapper

def unmap(mapper,arr):
  otp=0
  for i in mapper:
    otp = otp*10
    otp = otp+arr.index(i)
  return otp

# Below are the public specs for Bitcoin's curve - the secp256k1
Pcurve = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1 # The proven prime
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field
Acurve = 0; Bcurve = 7 # This defines the curve. y^2 = x^3 + Acurve * x + Bcurve
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
GPoint = (Gx,Gy) # This is our generator point. Tillions of dif ones possible

#Individual Transaction/Personal Information
privKey = 75263518707598184987916378021939673586055614731957507592904438851787542395619 #replace with any private key
RandNum = 28695618543805844332113829720373285210420739438570883203839696518176414791234 #replace with a truly random number
HashOfThingToSign = 86032112319101611046176971828093669637772856272773459297323797145286374828050 # the hash of your message/transaction

def modinv(a,n=Pcurve): #Extended Euclidean Algorithm/'division' in elliptic curves
    lm, hm = 1,0
    low, high = a%n,n
    while low > 1:
        ratio = int(high/low)
        nm, new = hm-lm*ratio, high-low*ratio
        lm, low, hm, high = nm, new, lm, low
        
    return lm % n

def ECadd(xp,yp,xq,yq): # Not true addition, invented for EC. It adds Point-P with Point-Q.
    m = ((yq-yp) * modinv(xq-xp,Pcurve)) % Pcurve
    xr = (m*m-xp-xq) % Pcurve
    yr = (m*(xp-xr)-yp) % Pcurve
    return (xr,yr)

def ECdouble(xp,yp): # EC point doubling,  invented for EC. It doubles Point-P.
    LamNumer = 3*xp*xp+Acurve
    LamDenom = 2*yp
    Lam = (LamNumer * modinv(LamDenom,Pcurve)) % Pcurve
    xr = (Lam*Lam-2*xp) % Pcurve
    yr = (Lam*(xp-xr)-yp) % Pcurve
    return (xr,yr)

def EccMultiply(xs,ys,Scalar): # Double & add. EC Multiplication, Not true multiplication
  if Scalar == 0 or Scalar >= N: raise Exception("Invalid Scalar/Private Key")
  ScalarBin = str(bin(Scalar))[2:]
  Qx,Qy=xs,ys
  for i in range (1, len(ScalarBin)): # This is invented EC multiplication.
      Qx,Qy=ECdouble(Qx,Qy); # print ("DUB", Qx)
      if ScalarBin[i] == "1":
          Qx,Qy=ECadd(Qx,Qy,xs,ys); # print ("ADD", Qx) 
  return (Qx,Qy)

print("******* Public Key Generation *********")
xPublicKey, yPublicKey = EccMultiply(Gx,Gy,privKey)
print ("the private key (in base 10 format):"); 
print(privKey)
print ("the uncompressed public key (starts with '04' & is not the public address):")
print ("04",xPublicKey,yPublicKey)

Message=input("Message : ")
Message=otp(int(Message))

print("Encrpytion")
print("Mapped message : ",Message)
xRandSignPoint, yRandSignPoint = EccMultiply(Gx,Gy,RandNum)
c1 =(xRandSignPoint%N,yRandSignPoint%N)
print ("c1 =", c1)
kQ1,kQ2=EccMultiply(xPublicKey,yPublicKey,RandNum)
cypher2=[]
for i in Message:
  cypher2.append(((i[0]+kQ1)%N,(i[1]+kQ2)%N))
print("c2 : ",cypher2)

print("Decryption")
dc1=EccMultiply(xRandSignPoint%N,yRandSignPoint%N,privKey)
print("dc1 : ",dc1)
decrypted=[]
for i in cypher2:  
  decrypted.append((i[0]-dc1[0],i[1]-dc1[1]))
print("Decrypted :",decrypted)
print("Unmap : ",unmap(decrypted,arr))
input("Press enter to close program")
