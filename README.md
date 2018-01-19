# Set default S3 bucket policy
This script takes a list of all buckets in an AWS Account.
It compares the existing bucket policy with a default policy defined as values in the script:
```
...[snip]...
34 rule_bucket_name = 'lifecyclebucket2'
35 default_policy_file = '_default.cfg'
...[snip]...
```
The script will try to add this default policy to the existing bucket policy.
It will log an error if:
- the same policy is already applied to the bucket under a 'prefix' or folder
- the same policy is already applied but has a differing value

Example of a _default.cfg file:
[default]
Setting = AbortIncompleteMultipartUpload
DaysAfterInitiation = 7
