import sys, subprocess, hashlib
import string
import math


def MGF(mgfSeed, maskLen) :
  hLen = 40
  if (maskLen > (2**32) * hLen) :
    return "Mask too long"

  T = ""

  for counter in range(0, ((maskLen + hLen - 1) / hLen)) :
    #print(range(0, (maskLen / 40) - 1))
    c = I20SP(counter, 4)
    #print("c ", c)
    hashs = hashlib.sha1((mgfSeed + c).decode("hex")).hexdigest()
    #print("hash, ", hash)
    T += hashs
  #print(T)
  T.zfill(maskLen)
  return T[:maskLen]

def I20SP(x, xLen) :
  #xLen is 4
  if x >= (256**(xLen-1)):
    return 

  result = "%x" % x
  #print ("I20SP ", result.zfill(2*xLen))
  return result.zfill(2*xLen)

def readFile(src) :
  file = open(src, "r")
  array = []
  for line in file:
    array.append(line)
  file.close
  return ( array[0], array[1], array[2] ) #return N, e, c

def interact( c ) :

  if(len(c) != 256):
    cc = c.zfill(256)
    #print (cc)
    target_in.write( "%s\n" % ( cc ) ) ; target_in.flush()
  else:
  # Send      G      to   attack target.
    target_in.write( "%s\n" % ( c ) ) ; target_in.flush()

  # Receive error code from attack target.
  error_code = ( target_out.readline().strip() )
  
  return ( error_code )

def attack(N_s, e_s, c_s) :
  
  f = 1
  e = int(e_s, 16)
  N = int(N_s, 16)
  c = int(c_s, 16)

  ################
  
  k = int(math.ceil(math.log(N, 256)))
  #print(k)
  B = pow(2,(8*(k-1)))
  #print("b",type(B))
  #################
  ##  Step 1    ###
  #################
  error_code = 0
  while (error_code != '1'):
    f *= 2
    c_res = str(hex((pow(f, e, N) * c ) % N)[2:-1])  
    ( error_code) = interact( c_res )
    # print "code = %s" % error_code 
    # print f 
  
  # #################
  # ##    Step 2   ##
  # #################

  f2 = (N+B)/B * f/2

  c_res1 = str(hex((pow(f2, e, N) * c ) % N)[2:-1])
  ( error_code) = interact( c_res1 )

  if (error_code == '2'):
    print "code = %s" % error_code #err code 2

  while (error_code != '2'):
    f2 += f/2
    c_res = str(hex((pow(f2, e, N) * c ) % N)[2:-1])
    ( error_code) = interact( c_res )
    ##if (error_code == '2'):
      # print "code = %s" % error_code #err code 2
      # print f2

  # #################
  # ##    Step 3   ##
  # #################

  m_min = (N+f2-1) / f2
  m_max = ((N+B) / f2)

  if (m_min == m_max):
    return m_max

  while (m_min != m_max):
    #print(m_max - m_min)
    f_tmp = (2*B / (m_max - m_min))

    i = (f_tmp * m_min / N)

    f3 = ((i*N)+m_min - 1 ) / m_min

    c_res = str(hex((pow(f3, e, N) * c ) % N)[2:-1])
    ( error_code) = interact( c_res )

    if (error_code == '1'):
      m_min = ( (i * N) + B + f3 -1 ) / f3 
      #print( m_min)
    if (error_code == '2'):
      m_max = ( ( i * N ) + B ) / f3  
      #print( m_max)
    if (m_min == m_max):
      # print("max:", m_max)
      # print("min", m_min)
      #print(hex(m_max))
      EM = hex(m_max).strip("L")[2:]
      if len(EM) != 256: 
         EM = EM.zfill(256)
      # print(len(EM))
      # print(EM)
      break
  
  ####################
  ##    DECODE EM   ##
  ####################
  #print(EM)
  #EM = '00ceef80bef423f058a1b971066750d4ecdb4ef17546c20627a36ef72d26776ff4f9567678f0a9c81b50f198d73fb3336296dc50763077efcba4e4ac6039535b8f32b92b9d4352af6f1bdc6d36be246a4939b02df9a1b4e75ce2120db96516fba4b7376450fd7b0434be74866566b44dbe88cce6dbf491b18d070e71839bd355'
  #lHash = hashlib.sha1("").hexdigest()
  #print lHash
  #hLen = len(lHash)
  #print EM
  Y = EM[:2]
  if (Y != '00') :
     return
  #print EM
  maskedSeed = EM[2:42]
  #print(len(maskedSeed))
  maskedDB = EM[42:]
  #print(len(maskedDB))
  # # #hLen = 40
  seed = (hex(int(maskedSeed, 16) ^ int(MGF(maskedDB, 40), 16)))[2:-1]
  #print(len(seed))
  DB = (hex(int(maskedDB, 16) ^ int(MGF(seed, 2*k-40-2), 16)))[2:-1]
  #print DB

  #lHash = DB[:40]

  DB = DB[40:]
  #print DB
  count = 0
  
  while DB[count] == '0':
    count += 1
  
  DB = DB[count+1:]
  print "Message: " + DB

  uid = DB[0:4]
  b1 = uid[0:2]
  b2 = uid[2:]
  final = b2 + b1
  print ("Final result: " + str(int(final, 16))) 
  print ("Uid for cs12751: " + "10363") 

if ( __name__ == "__main__" ) :
  # Produce a sub-process representing the attack target.
  target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE, 
                             stdin  = subprocess.PIPE )

  # Construct handles to attack target standard input and output.
  target_out = target.stdout
  target_in  = target.stdin

  (N, e, c) = readFile(sys.argv[2])

  # Execute a function representing the attacker.
  attack(N, e, c)

