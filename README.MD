## Bucket Analyzer S3

![bas3 version](https://img.shields.io/badge/version-v1.0-blue) ![python version](https://img.shields.io/badge/python-v3.6+-green)

![image-20220912101401930](https://github.com/secureITmania/bas3/blob/master/asset/image-20220912101401930.png)

#### Installation

```
$ git clone https://github.com/secureITmania/bas3.git
$ cd bas3
$ python3 -m pip install -r requirements.txt
```

#### Usage

```
usage: bas3.py [-h] --bucket BUCKET [--json JSON] [--raw] [--silent]

optional arguments:
  -h, --help       show this help message and exit
  --bucket BUCKET  Input bucket name
  --json JSON      Write verbose result in JSONL format ex: --json file.json
  --raw            Show crisp output in a raw format stdout, default value is false
  --silent         Display findings only
```
