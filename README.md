# Automated GitHub Actions Trust Policy validation with AWS Config

This repository contains custom AWS Config rule built using the AWS [Rule Development Kit](https://github.com/awslabs/aws-config-rdk) (RDK). This rule is designed to validate that an IAM role created to use [OpenID Connect with GitHub Actions](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services) has an IAM Trust Policy that aligns with the Amazon IAM best practice of granting least privilege. The IAM Trust Policy should contain a Condition that specifies a subject (sub) allowed to assume the role. Without a subject (sub) condition, any GitHub user or repository could potentially assume the role. 

The logic contained within this AWS Config Rule is provided as an example, but should be extended as required to support the business logic required to validate the subjects that can assume a role. For example, looking up a known list of trusted GitHub Organizations and repositories, and then validating that the job was run from a workflow referencing an environment called "Production".

See [Example Subject Claims](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#example-subject-claims) for examples on different subject values that should be checked for your specific business requirements.

## Getting Started

This rule requires the use of [RDK](https://github.com/awslabs/aws-config-rdk#getting-started) and [RDKlib](https://github.com/awslabs/aws-config-rdklib) to deploy. 

## Requirements

1. An AWS account with permissions to create the necessary resources.
2. A [GitHub account](https://github.com/) configured to use GitHub Actions.
3. A [Git client](https://git-scm.com/downloads) to clone the provided source code.
4. A [supported](https://github.com/awslabs/aws-config-rdk#getting-started) Python runtime (Python 3.7+).

## Validation definition

We recommend defining custom logic within `github-actions-trust-check.py` (you will find these areas commented), see [AWS Config custom rule structure](https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_components.html#evaluate-config_components_logic) for more details on the evluation logic. The base logic in this rule will first check that a condition key exists for `token.actions.githubusercontent.com:sub` in the trust policy, and then perforams a simple substring heck for the `TrustClaimSubject` property of the config rule against this condition keys value. You can update this property in `parameters.json` prior to deplyoing the rule via the RDK, or you can update the property for the AWS Config rule through the [AWS Console](https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_manage-rules.html#managing-aws-config-rules-with-the-console) or [AWS CLI](https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_manage-rules.html#managing-aws-config-rules-with-the-CLI).

## Testing your validation logic

The `sample.json` file contains an example payload sent to AWS Config for a new IAM role creation. The `assumeRolePolicyDocument` property is the IAM Role Trust Polciy stored as an escaped JSON string. The `sub:` property represents the subject that has been set by an IAM Trust Policy that is trusting GitHub Actions. In this sample, it is set to `repo:a-user-or-org-name/a-repo-name:*` and should be updated to reflect your organizations GitHub repository structure, using guidance from [Example Subject Claims](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#example-subject-claims).

You can locally test your logic against the sample payload by running a local test from the top level path you checked out this repository with `rdk test-local github-actions-trust-check`. The `github-actions-trust-check_test.py` file can be modified to support multiple sample files, or to support your custom validation logic as required.

## Deployment walkthrough

We recommend creating a Python [virtual environment](https://docs.python.org/3/library/venv.html) to avoid conflicts with multiple package versions in the core Python installation on your system.

1. Open a terminal and install the RDKlib package using `pip install rdklib`
2. Create a new empty directory and change into it
3. Clone this repository `git clone [repository]`
4. Run an `rdk init` - this will initialise RDK in the account and region that your AWS access credentials are pointed to.
5. Deploy the RDKlib Lambda layer using the following simplified instructions. These assume you are using a Linux or MacOS command line and have jq installed. Otherwise you can [install the serverless application through the console](https://console.aws.amazon.com/lambda/home#/create/app?applicationId=arn:aws:serverlessrepo:ap-southeast-1:711761543063:applications/rdklib).
    1. Run ``export CHANGE_SET=`aws serverlessrepo create-cloud-formation-change-set --application-id arn:aws:serverlessrepo:ap-southeast-1:711761543063:applications/rdklib --stack-name RDKlib-Layer | jq -r '.ChangeSetId'` ``
    2. Run `aws cloudformation execute-change-set --change-set-name $CHANGE_SET`
    3. Wait for the change set to change status to CREATE_COMPLETE, you can check with `aws cloudformation describe-change-set --change-set-name $CHANGE_SET | jq -r '.Status'`
    4. Run ``export RESOURCE_ID=`aws cloudformation describe-stack-resources --stack-name serverlessrepo-RDKlib-Layer | jq -r '.StackResources.[0].PhysicalResourceId'` ``
6. Deploy with `rdk deploy github-actions-trust-check --rdklib-layer-arn $RESOURCE_ID` where $RESOURCE_ID is the Lambda layer ARN deployed for RDKlib.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
