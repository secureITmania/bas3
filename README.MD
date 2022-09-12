## Bucket Analyzer S3

![bas3 version](https://img.shields.io/badge/version-v1.0-blue) ![python version](https://img.shields.io/badge/python-v3.6+-green)

![image-20220912101401930](data:image/png;base64,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)

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