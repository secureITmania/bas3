import urllib3
import argparse
import subprocess
import json
import pyfiglet

true = True
false = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
listObj = []

parser=argparse.ArgumentParser()

parser.add_argument('--bucket', type=str, required=True, help="Input bucket name")

parser.add_argument('--json', type=str, help="Write verbose result in JSONL format ex: --json file.json")
parser.add_argument('--raw', action="store_true", help="Show crisp output in a raw format stdout, default value is false")
parser.add_argument('--silent',action="store_false", help="Display findings only")
# Parse the argument
args = parser.parse_args()

awsout=subprocess.run(['aws','s3','ls'], capture_output=True)
outerr=str(awsout.stderr)
if "Unable to locate" in outerr:
    print("Error: Please configure aws cli with your access credentials")
    exit()

if args.silent == True:
    ascii_banner = pyfiglet.figlet_format("BAS3")
    print(ascii_banner+"Bucket Analyzer S3 v1.0\n\n")

def anonymousAccess(bucket_url,region):
    try:
        http = urllib3.PoolManager()
        r = http.request('GET', bucket_url)
        if r.status == 200:
            a={"anonymous_access": true, "region":region, "vulnerable_url":bucket_url}
            listObj.append(a)
    except urllib3.exceptions.HTTPError as e:
        error=e.reason


def arbitraryListing(bucketname):
    cmd="s3://"+bucketname
    proc=subprocess.run(['aws','s3','ls',cmd], capture_output=True)
    aa=str(proc.stdout,'utf-8')

    bb=str(proc.stderr,'utf-8')
    if "An error" in bb:
        al={"arbitraryListing": false,
            "result":bb}
        listObj.append(al)
    elif proc.returncode == 0:
        ll=aa.split('\n')
        tl={"arbitraryListing":True,
                "result":ll[:4],
                "total_files":len(ll)}
        listObj.append(tl)
        #print(ll[:4])

def arbitraryFileUpload(bucketname):
    cmd="s3://"+bucketname
    proc2=subprocess.run(['aws','s3','cp','./asset/poc.jpg',cmd], capture_output=True)
    fur=str(proc2.stdout, 'utf-8')
    fue=str(proc2.stderr, 'utf-8')
    if proc2.returncode == 0:
        afu={"arbitraryFileUpload": true,"result":fur}
        listObj.append(afu)
    else: 
        afe={"arbitraryFileUpload": false,"result":fue}
        listObj.append(afe)


 #print(proc2)

def readableBucketPolicy(bucketname):
    proc3=subprocess.run(['aws','s3api','get-bucket-policy','--bucket',bucketname], capture_output=True)
    rbr=str(proc3.stdout, 'utf-8')
    rbe=str(proc3.stderr, 'utf-8')
    if proc3.returncode == 0:
        rbp={"readableBucketPolicy": true,"result":rbr}
        listObj.append(rbp)
    else:
        rber={"readableBucketPolicy": false,"result":rbe}
        listObj.append(rber)
    #print(proc3)

def getBucketAcl(bucketname):
    proc4=subprocess.run(['aws','s3api','get-bucket-acl','--bucket',bucketname], capture_output=True)
    gbr=str(proc4.stdout, 'utf-8')
    gbe=str(proc4.stderr, 'utf-8')
    #print(proc4)
    if proc4.returncode == 0:
        gba={"getBucketAcl": true,"result":gbr}
        listObj.append(gba)
    else:
        gber={"getBucketAcl": false,"result": gbe}
        listObj.append(gber)

#Output Analyser and reformatter
def outputHandler(f_output,message):
    if len(f_output)==0:
        aa={ message : false,"result":"The bucket is not vulnerable to anonymous access"}
        #print(aa)
        listObj.append(aa)

def rawOutput(jsonObj, bucketname):
    data=json.loads(jsonObj)
    if len(data) == 6:
        ac=data[0]["anonymous_access"]
        al=data[2]["arbitraryListing"]
        afu=data[3]["arbitraryFileUpload"]
        rbp=data[4]["readableBucketPolicy"]
        gbc=data[5]["getBucketAcl"]
        out="[S3 Bucket: {bucket}] [anonymousAccess: {ac}] [arbitraryListing: {al}] [arbitraryFileUpload: {afu}] [readableBucketPolicy: {rbp}] [getBucketAcl: {gbc}]".format(ac= ac, al=al, afu=afu, rbp=rbp, gbc=gbc, bucket=bucketname)
        print(out)
    else:
        ac=data[0]["anonymous_access"]
        al=data[1]["arbitraryListing"]
        afu=data[2]["arbitraryFileUpload"]
        rbp=data[3]["readableBucketPolicy"]
        gbc=data[4]["getBucketAcl"]
        out="[S3 Bucket: {bucket}] [anonymousAccess: {ac}] [arbitraryListing: {al}] [arbitraryFileUpload: {afu}] [readableBucketPolicy: {rbp}] [getBucketAcl: {gbc}]".format(ac= ac, al=al, afu=afu, rbp=rbp, gbc=gbc, bucket=bucketname)
        print(out)



# Parse the argument
regions = ["s3-ap-northeast-1","s3-ap-northeast-2","s3-ap-northeast-3","s3-ap-south-1","s3-ap-southeast-1","s3-ap-southeast-2","s3-ca-central-1","s3-cn-north-1","s3-eu-central-1","s3-eu-west-1","s3-eu-west-2","s3-eu-west-3","s3-sa-east-1","s3-us-east-1","s3-us-east-2","s3-us-west-1","s3-us-west-2","s3"]
for i in regions:
    s3url="https://"+args.bucket+"."+i+".amazonaws.com"
    anonymousAccess(s3url,i)


#arbitraryListing(args.bucket)

f_output=outputHandler(listObj,"anonymous_access")
arbitraryListing(args.bucket)
arbitraryFileUpload(args.bucket)
readableBucketPolicy(args.bucket)
getBucketAcl(args.bucket)
#print(listObj)
jj=json.dumps(listObj)
#print(jj)
if args.raw == True:
    rawOutput(jj,args.bucket)
if args.json is not None:
    with open(args.json, "w") as outfile:
        outfile.write(jj)

