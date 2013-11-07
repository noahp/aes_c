
'''
    From the NIST zip distribution, extract the ECB test vectors and create
    c code versions of them for the unit test to run.

    Vectors from here pulled on 2013-11-06:
    http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip
'''

import sys, os, re, fileinput, string, zipfile

H_FILE_TEMPLATE = '''
//
// aes_testvectors.h
// set of test vectors for aes_tests
//

#define AES_TESTVECTORS_SIZE 16

typedef struct aestestvectors_s {
    int idx;
    unsigned char key[AES_TESTVECTORS_SIZE];
    unsigned char plaintext[AES_TESTVECTORS_SIZE];
    unsigned char ciphertext[AES_TESTVECTORS_SIZE];
} aestestvectors_t;

const aestestvectors_t aestestvectors[%s] = {
%s};
'''

VECTOR_ENTRY_TEMPLATE = '''    {
        .idx =          %s,
        .key =          {%s},
        .plaintext =    {%s},
        .ciphertext =   {%s},
    },
'''

if len(sys.argv) < 2:
    print "Please pass a zipfile argument."
    sys.exit(-1)

def string_to_byte_array(instring):
    bytes = zip(instring[::2],instring[1::2])
    return ','.join(['0x%02X'%(int(x+y,16)) for x,y in bytes])

# alias
STBA = string_to_byte_array

zipfilename = sys.argv[1]

TEST_VECTOR_FILTER_LIST = [ 'ECBGFSbox128.rsp',
                            'ECBKeySbox128.rsp',
                            'ECBVarKey128.rsp',
                            'ECBVarTxt128.rsp']

testdata = []
count = 0
file = zipfile.ZipFile(zipfilename, "r")
for name in file.namelist():
    if name in TEST_VECTOR_FILTER_LIST:
        print "Loading vectors from: " + name
        data = file.read(name)
        keys = re.findall('KEY = (.*)\r\n', data)
        plaintexts = re.findall('PLAINTEXT = (.*)\r\n', data)
        ciphertexts = re.findall('CIPHERTEXT = (.*)\r\n', data)

        # make sure key,plaintext,ciphertext sets are complete
        if len(keys) != len(plaintexts) or len(plaintexts) != len(ciphertexts):
            print "Oops didn't get complete set of vectors from: %s"%name
            sys.exit(-1)
        counts = xrange(count, count+len(keys))
        count = count + len(keys)
        testdata.extend(zip(counts,keys, plaintexts, ciphertexts))

testdata = ''.join([VECTOR_ENTRY_TEMPLATE%(cnt,STBA(k),STBA(p),STBA(c)) for cnt,k,p,c in testdata])
testdata = H_FILE_TEMPLATE%(count,testdata)

# write out
with open('aes_testvectors.h', 'w') as file:
    file.write(testdata)
