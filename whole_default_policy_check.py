from __future__ import print_function

import boto3
import sys
import ConfigParser
import io

from botocore.exceptions import ClientError

'''
        There are 6 possible states of the lifecycle policy for a bucket:
        - it doesn't have any applied lifecycle policies
        - it has policies but they are all applied to prefixes, no desired action is in those policies
        - it has policies but they are all applied to prefixes, and the desired actio is there (we do not work on these, pass)
        - it has a whole bucket policy but the desired action isn't applied to the whole bucket policy (Prefix = '')
        - it has a whole bucket policy and the desired action is applied but the value is wrong
        - it has a whole bucket policy and the desired action is applied and the value is correct

        For each bucket name in no policies, just apply the policy (mimic with mocking what would send)
        
	For no matching rule, evaluate if the applied rules have a prefix = ''
        
	If there is a prefix = '', then take all actions that aren't already in that


 In this example, the _default.cfg file contains the following:

  [default]
  Setting = AbortIncompleteMultipartUpload
  DaysAfterInitiation = 7
'''


rule_bucket_name = 'lifecyclebucket2'
default_policy_file = '_default.cfg'

# When there's no region, the standard bucket throws a hissy fit even if you do include a region
init_client = boto3.client('s3')

resource = boto3.resource('s3')

def get_s3_client(bucket_name):
    region = init_client.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
    if not region:
        region = 'us-east-1'
    client = boto3.client('s3', region_name=region)
    return client

# This parses a simple config file stored in an S3 bucket.

def parse_config():
    '''Parsing a config file that is written in a basic ConfigParser syntax key=value'''
    config = ConfigParser.SafeConfigParser()
    rule_bucket_name = 'lifecyclebucket2'
    default_policy_file = '_default.cfg'
    config.optionxform = str
    #rule_bucket = resource.Bucket(rule_bucket_name)
    default_policy_object = init_client.get_object(Bucket=rule_bucket_name, Key=default_policy_file)
    default_policy = unicode(default_policy_object['Body'].read())
    config.readfp(io.StringIO(default_policy))
    sections = config.sections()
    desired_policies = []
    for section in sections:
        policy = {}
        values = {}
        options = config.options(section)
        if section == 'default':
            policy['Prefix'] = ""
        for option in options:
            if option == 'Setting':
                action = config.get(section, option)
            if option != 'Setting':
                values[option] = int(config.get(section, option))
        policy['Status'] = 'Enabled'
        policy[action] = values
        desired_policies.append(policy)
        print('Desired policies: {0}'.format(str(desired_policies)))
    # Returning: policy as a dictionary, desired policies collected into a list, and the action to be taken on the object
    return(policy, desired_policies, action)
 
def get_bucket_list():
    buckets = init_client.list_buckets()
    bucket = buckets['Buckets']
    return bucket
    
def get_bucket_lifecycle_rules(item, bucket):
        bucket_name_and_policies = {}
        bucket_name = bucket[item]['Name']
        bucket_name_and_policies['bucket_name'] = bucket_name
	client = get_s3_client(bucket_name)
        try:
            bucket_lifecycle = client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            bucket_name_and_policies['Rules'] = bucket_lifecycle['Rules']
            return bucket_name_and_policies, bucket_name, client
        except ClientError as e:
            print('Checking the bucket lifecycle configuration raised this error: ' + str(e))
            no_rules = []
            rule_item = {}
            rule_item['Status'] = 'None'
            no_rules.append(rule_item)
            bucket_name_and_policies['Rules'] = no_rules
            return(bucket_name_and_policies, bucket_name, client)

def has_policies(lifecycle_rule_policies):
    bucket = get_bucket_list()
    for item in range(len(bucket)):
        bucket_name_and_policies, bucket_name, client = get_bucket_lifecycle_rules(item, bucket)
        lifecycle_rule_policies.append(bucket_name_and_policies)
    return lifecycle_rule_policies

def add_policy_to_existing_policies(bucket_rules, desired_policy):
    '''
    The bucket policies do not cover the whole bucket policy so they can be appened
    to the Rules list
    '''
    bucket_rules.append(desired_policy)
    return(bucket_rules)

def add_policy_to_existing_rule(whole_bucket_lifecycle_rule, desired_policy):
    ''' If NO applied policies match but there is a policy that covers the entire bucket (Prefix = ''),
    put the desired action inline with the policy that covers the whole bucket
    But, one needs to get all lifecycle policies because if you put a new lifecycle policy, it'll overwrite all
    applied lifecycle policies in the bucket
    '''
    desired_keys = desired_policy.keys()
    applied_keys = whole_bucket_lifecycle_rule.keys()
    for k in desired_keys:
        if k not in applied_keys:
            whole_bucket_lifecycle_rule[k] = desired_policy[k]
    return(whole_bucket_lifecycle_rule)

def lifecycle_no_prefix_policy(bucket_name, policies):
    '''
    Finds if there is a Lifecycle Policy applied to the whole bucket
    '''
    whole_bucket_policy = ''
    policies_with_prefixes = []
    for entry in policies:
        if bucket_name in entry['bucket_name']:
            all_policies_for_bucket = entry['Rules']
            for policy in entry['Rules']:
                if policy['Prefix'] == '':
                    whole_bucket_policy = policy
		else:
		    print('This is the bucket %s and this is the current policy: %s' % (bucket_name, policy))
		    policies_with_prefixes.append(policy)
    return(whole_bucket_policy, all_policies_for_bucket, policies_with_prefixes)

def add_policy_to_no_rules(desired_policy):
    new_policies = []
    '''This will just append the desired policy to the list of rules.
       Existing rules are all prefixed or there are no rules at all
       But, one needs to get all lifecycle policies applied to the bucket because when putting a new lifecycle policy,
       it will overwrite all of the lifecycle policies applied to the bucket
    '''
    new_policies.append(desired_policy)
    return(new_policies)

def prefix_match(rule_value_match, desired_policy):
    '''
    In this fucntion, we will compare the Prefixes for the lifecycle polciy action value match and see if
    the policy is in place for the desired prefix
    '''
    wrong_prefix = {}
    correct_prefix = {}
    if rule_value_match['Prefix'] == desired_policy['Prefix']:
        correct_prefix['bucket_name'] = rule_value_match['bucket_name']
    else:
        wrong_prefix['bucket_name'] = rule_value_match['bucket_name']
        wrong_prefix['BucketPrefix'] = rule_value_match['Prefix']
        wrong_prefix['DesiredPrefix'] = desired_policy['Prefix']
    return(correct_prefix, wrong_prefix)

def value_match(key_match, bucket_and_policies, desired_policy):
    '''
Getting the key that matched and bucket name from matched list, then compare the value from the
buckets_and_policies to the value in desired_policy
    '''
    rule_matched_desired_value = {}
    no_rule_matched_desired_value = {}
    matched_key = key_match['Key']
    for entry in bucket_and_policies:
        if key_match['bucket_name'] in entry['bucket_name']:
            for rule in entry['Rules']:
                if matched_key in rule:
                    if rule[matched_key] == desired_policy[matched_key]:
                        # Here, we will create a dictionary with the bucket name, the desired action, and the action value
                        rule_matched_desired_value['bucket_name'] = key_match['bucket_name']
                        rule_matched_desired_value['MatchedKey'] = matched_key
                        rule_matched_desired_value['MatchedValue'] = rule[matched_key]
                        rule_matched_desired_value['Prefix'] = rule['Prefix']
                    else:
                        no_rule_matched_desired_value['bucket_name'] = key_match['bucket_name']
                        no_rule_matched_desired_value['Prefix'] = rule['Prefix']
                        no_rule_matched_desired_value['MatchedKey'] = matched_key
                        no_rule_matched_desired_value['WrongValue'] = rule[matched_key]
                        no_rule_matched_desired_value['DesiredValue'] = desired_policy[matched_key]
    return(rule_matched_desired_value, no_rule_matched_desired_value)

# Does the key exist in this rule - a bucket can have many rules
def action_match_or_not(rule, bucket_name, desired_policies):
    matching_key = 0
    key_matched = {}  # This keeps a record of which key was matched inside the Lifecycle Policy
    '''This goes through 1 rule and checks to see if the action - or key - exits in the entire rule'''
    for desired_policy in desired_policies:
        for k in desired_policy:
            if k not in ['Prefix', 'Status', 'ID']:
                # Go through each policy dictionary in the desired policies list
                if k in rule.keys():
                    matching_key += 1
                    key_matched['Key'] = k
    return(matching_key, key_matched)

def desired_action_exists(buckets_and_policies, desired_policies):
    '''
    buckets_and_policies is the list of ALL buckets and their lifecycle policies
    This function is supposed to see if there are any applied policies that exist with the desired action.
    This goes through EACH policy applied to each bucket Lifecycle and evaluates the rules as a whole
    '''
    no_policies = []
    key_matches = []
    no_key_matches = []
    for entry in buckets_and_policies:
        is_key_matched = 0
        matching_key = 0
    # For EACH lifecycle policy in this bucket, if the status is none, add it to the no_policies list.
    # Else - check to see if it has a matching key/action
        for rule in entry['Rules']:
            if rule['Status'] == 'None':
                no_policies.append(entry['bucket_name'])
            else:
                matching_key, rule_key_matched = action_match_or_not(rule, entry['bucket_name'], desired_policies)
                if rule_key_matched:
                    key_matched = rule_key_matched
            is_key_matched += matching_key # This is to keep track while going through all rules
        if is_key_matched > 0:
            key_matched['bucket_name'] = entry['bucket_name']
            key_matches.append(key_matched)
        elif entry['bucket_name'] not in no_policies:
            no_key_matches.append(entry['bucket_name'])
    return(no_policies, key_matches, no_key_matches)

def put_new_policies(bucket_name, policy_to_apply):
    '''
    This is where the default policy is applied to the bucket
    '''
    client = get_s3_client(bucket_name)
    print('Applying new lifecycle policy to bucket %s' % bucket_name)
    put_policy_response = client.put_bucket_lifecycle_configuration(
		    Bucket=bucket_name,
		    LifecycleConfiguration={
			    'Rules': policy_to_apply
		    }
		)
    print('Putting the policy response: ' + str(put_policy_response))
    return(put_policy_response)

def lambda_handler(event, context):
    print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
    desired_policy, desired_policy_list, desired_action = parse_config()
    lifecycle_rule_policies = []
    rule_value_matches = []
    no_rule_value_matches = []
    correct_policy = []
    wrong_prefix_policy = []
    '''
    From all the buckets within the AWS Account, get a list of buckets and their LifeCycle policies
    If the bucket has no LifeCycle policies attached, it will have a Rules list who's 'Status' key has the value of 'None'

    has_policies RETURNS A LIST OF BUCKETS AND THEIR LIFECYCLE POLICIES
    '''
    policies = has_policies(lifecycle_rule_policies)
    no_policies, key_matches, no_key_matches = desired_action_exists(policies, desired_policy_list)
    for match in key_matches:
        action_value_match, no_action_value_match = value_match(match, policies, desired_policy)
        if action_value_match:
            rule_value_matches.append(action_value_match)
        if no_action_value_match:
            no_rule_value_matches.append(no_action_value_match)
    print('These had rules whos values DID NOT MATCH the desired lifecycle policy: ' + str(no_rule_value_matches))
    print()
    for valuematch in rule_value_matches:
        correct_prefix, wrong_prefix = prefix_match(valuematch, desired_policy)
        if correct_prefix:
            correct_policy.append(correct_prefix)
        if wrong_prefix:
            wrong_prefix_policy.append(wrong_prefix)
    print('These buckets have the correct policy! Rejoice! ' + str(correct_policy))
    print()
    print('These are the buckets have the desired action but the action is applied to prefixes that are incorrect. Shame. ' + str(wrong_prefix_policy))
    print()

    '''
    This for loop calls the function to add the default lifecycle policy
    to buckets that have no current lifecycle policies applied
    '''
    for bucket in no_policies:
        new_policy = add_policy_to_no_rules(desired_policy)
        print('There were no policies applied to this bucket. This is the new policy for bucket %s: %s' % (bucket, str(new_policy)))
	'''
	To put default policy, uncomment below
	'''
        #response = put_new_policies(bucket, new_policy)

    '''
    Here, we want to take the no key matches, and add it to the prefix
    Have to first see if there is a policy with a prefix.
    If there is no prefix, then just append the already set up policy to the Rule list
    If there is one, find the key in the desired policy that is missing from the applied policy and add it
    '''
    for bucket in no_key_matches:
        print()
        '''
        no prefix policy means this lifecycle policy has a rule that has Prefix = ''
        Prefix = '' means it covers the whole bucket so have to be careful how the default
        action is inserted into this existing whole bucket lifecycle policy
        '''
        no_prefix_policy, policies_applied_to_bucket, policies_to_apply = lifecycle_no_prefix_policy(bucket, policies)
        if no_prefix_policy:
	    '''
            Then the bucket has a policy applied to the whole bucket
            Need to find the acation that's not included and apply it to get a new whole bucket policy
	    '''
            whole_bucket_policy = add_policy_to_existing_rule(no_prefix_policy, desired_policy)
            print('This is the new whole bucket policy for bucket %s: %s ' % (bucket, str(whole_bucket_policy)))
            policies_to_apply.append(whole_bucket_policy)
	    print('These are new policies to be applied to the S3 bucket %s: %s' % (bucket, str(policies_to_apply))) 
        else:
	    '''
        We will just append the existing desired policy to the rules that are already applied
            '''
	    policies_to_apply = add_policy_to_existing_policies(policies_applied_to_bucket, desired_policy)
            print('This is the whole new bucket policy for bucket %s: %s' % (bucket, str(policies_to_apply)))
	'''
	If desired, uncomment this to put the new bucket policies
	'''
	#response = put_new_policies(bucket, policies_to_apply)
        	    
def main():
    lambda_handler("thing", "thing2")

if __name__ == "__main__":
    sys.exit(main())
