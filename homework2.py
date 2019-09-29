import numpy as np

key = 0
k1 = []
k2 = []
plain_text = [] #8bit
ciphertext = [] #8bit
Round = 0
test = [1,0,1,0,0,0,0,0,1,0]
#description
IP = [2, 6, 3, 1, 4, 8, 5, 7]
FP = [4, 1, 3, 5, 7, 2, 8, 6]
#permutation
p10 = [3,5,2,7,4,10,1,9,8,6]  
p8 = [6,3,7,4,8,5,10,9] 
#fkfunction
EP = [4, 1, 2, 3, 2, 3, 4, 1]
S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]
P4 = [2, 4, 3, 1]
ip = []
cip =[ 0b1111110,0b10001,0b11101110,0b110100,0b111111,0b11101110,0b110100,0b111111,0b111111,0b10110101,0b1111110,0b11101110,0b101000,0b111111,0b10110101,0b10001,0b10111111,0b10001,0b101000,0b10001011,0b101000,0b10111111,0b1111110,0b11101110,0b101000,0b101000,0b11101110,0b10001011,0b10001,0b10111111,0b1111110,0b110100,0b111111,0b11101110,0b10111111,0b1111110,0b11111110,0b111111,0b110100,0b101000,0b11101110,0b111111,0b111111,0b10110101,0b11101110,0b11101110,0b11111110,0b10111111,0b101000,0b110100,0b11111110,0b11111110,0b11101110,0b110100,0b10110101,0b110100,0b101000,0b10111111,0b101000,0b101000,0b11101110,0b11101110,0b10001011,0b110100,0b1111110,0b110100,0b11111110,0b10110101,0b101000,0b101000,0b10001011,0b10111111,0b111111,0b10001011,0b10111111,0b111111, ]
valid = []
student_id =[5,9,0,6,1,0,6,1,1]
def rotate(l, n):
    return l[n:] + l[:n]

def convert(list): 
      
    # Converting integer list to string list 
    s = [str(i) for i in list] 
      
    # Join list items using join() 
    res = int("".join(s)) 
      
    return(res)
def generate_key(key = []) :
    makeup_key = []
    for i in range(len(p10)):       
        makeup_key.append(key[p10[i]-1])   
    #print(makeup_key)
    key_L = makeup_key[0:5]
    key_R = makeup_key[5:10]
    #print(key_L,key_R)
    #k1
    key_L = rotate(key_L,1)
    key_R = rotate(key_R,1)
    #print("shift:",key_L,key_R)
    key = key_L+key_R
    #print("to_p8:",key)
    makeup_key1 = []
    
    for i in range(len(p8)):       
        makeup_key1.append(key[p8[i]-1])
    k1 = makeup_key1
    #print("k1" , k1)
    
    #k2
    key_L = rotate(key_L,2)
    key_R = rotate(key_R,2)
    key = key_L+key_R
    makeup_key1 =[]
    #print("shift2:",key_L,key_R)
    for i in range(len(p8)):       
        makeup_key1.append(key[p8[i]-1])
    k2 = makeup_key1
    # print("key :",test)
    # print("k1 :" ,k1)
    # print("k2 :" ,k2)
    return k1,k2
def ep(tm_data,data):
    makeup_ = []
    for i in range(len(data)):
        makeup_.append(tm_data[EP[i]-1])
    return makeup_

def swap(_data):
    tmp = int(_data[0:4],2)
    tmp2 = int(_data[4:8],2)<<4
    return format(tmp^tmp2,'08b')



        


    
def fk(key_,data):
    # print(ep(data[5:10],data))
    # print("EP >> 4:",ep(data[4:8],data))
    # print("EP << 4:",data[0:4])
    _ep_L = data[0:4]
    _ep_R = ep(data[4:8],data)

    bit = int(str(convert(_ep_R)),2)
    bit2 = int(str(convert(key_)),2)
    tmp =format(bit ^ bit2,'08b')

    tmp1 = tmp[0:4]
    tmp2 = tmp[4:8]
    _s0 = S0[int(tmp1[0]+tmp1[3],2)][int(tmp1[1]+tmp1[2],2)]
    _s1 = S1[int(tmp2[0]+tmp2[3],2)][int(tmp2[1]+tmp2[2],2)]
    tmp = _s0 << 2
    tmp = tmp + _s1
    tmp = format(tmp,'04b')
    make = []
    for i in range(len(P4)):
        make.append(tmp[P4[i]-1])
    _p4 =format(int(str(convert(make)),2),'04b')
   
    bit1 = int(str(convert(_ep_L)),2)
    bit2 = int(_p4,2)
    tmp =format(bit1 ^ bit2,'04b')
    tmp2 =format(int(str(convert(data[4:8])),2),'04b')
    

    return tmp+tmp2


def fp(input):
    makeup_key = []
    for i in range(len(FP)):       
        makeup_key.append(input[FP[i]-1])
    return makeup_key
def ip(input ):
    makeup_key = []
    for i in range(len(IP)):       
        makeup_key.append(input[IP[i]-1])
    return makeup_key

def decrypt(_k1 = [],_k2 = [],_ciphertext =[]):
    _ip = ip(_ciphertext)
    data = fk(_k1, _ip)
    return fp(fk(_k2, swap(data)))  
# cip_index = []
# byte = format(cip[2],'08b')
# for k in range(8):
#     cip_index.append(int(byte[k]))
# print(cip_index)
add =  []
sd = [0,0,0,0,0,0,0,0,0]
for i in range(int('1111111111',2)):
    key_list = []
    key3 = format(i,'010b')
   
    for j in range(10):
        key_list.append(int(key3[j]))
    k1,k2 = generate_key(key_list)

    count = 0
    for m in range(len(student_id)):
        cip_index = []
        list_ = []
        byte = format(cip[m],'08b')
        num = 0
        for k in range(8):
            cip_index.append(int(byte[k]))
        list_ = decrypt(k2,k1,cip_index)
        num = int(str(convert(list_)),2)
        if(count < 9):
            if(num == student_id[m]):
                print(count,"Key :",key3,"s_id",student_id[m],"index",m)
                count+=1
        else:
            print("gggggg")
            break
plain_text = [] 
key_list =[]
key3 = '0100101010'
for j in range(10):
    key_list.append(int(key3[j]))
k1,k2 = generate_key(key_list)

for i in range(len(cip)):
    print(cip[i])
    byte = format(cip[i],'08b')
    num = 0
    for k in range(8):
        cip_index.append(int(byte[k]))
    list_ = decrypt(k2,k1,cip_index)
    num = int(str(convert(list_)),2)
    plain_text.append(cip[i])
print(plain_text)
