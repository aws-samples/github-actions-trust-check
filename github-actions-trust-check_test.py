import unittest
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError
import rdklib
from rdklib import Evaluation, ComplianceType
import json
import rdklibtest

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
RESOURCE_TYPE = 'AWS::IAM::Role'

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = False

#############
# Main Code #
#############

MODULE = __import__('github-actions-trust-check')
RULE = MODULE.githubActionsTrustChecker()

CLIENT_FACTORY = MagicMock()

# example for mocking IAM API calls
IAM_CLIENT_MOCK = MagicMock()

def mock_get_client(client_name, *args, **kwargs):
    if client_name == 'iam':
        return IAM_CLIENT_MOCK
    raise Exception("Attempting to create an unknown client")

@patch.object(CLIENT_FACTORY, 'build_client', MagicMock(side_effect=mock_get_client))
class ComplianceTest(unittest.TestCase):

    rule_parameters_compliant =     {'TrustClaimSubject': 'repo:a-user-or-org-name/a-repo-name'}
    rule_parameters_non_compliant = {'TrustClaimSubject': 'repo:a-user-or-org-name/a-non-compliant-repo-name'}

    configuration_item = json.load(open('github-actions-trust-check/sample.json'))
    invoking_event_iam_role_sample = {'configurationItemDiff':'SomeDifference', 'notificationCreationTime':'SomeTime', 'messageType':'ConfigurationItemChangeNotification', \
                                       'recordVersion':'SomeVersion', 'configurationItem': configuration_item}

    def setUp(self):
        pass

    def test_sample_compliant(self):
        response = RULE.evaluate_change(
            event=json.dumps(self.invoking_event_iam_role_sample),
            client_factory=CLIENT_FACTORY,
            configuration_item=self.configuration_item,
            valid_rule_parameters=RULE.evaluate_parameters(self.rule_parameters_compliant),
        )

        resp_expected = []
        resp_expected.append(Evaluation(
                complianceType=ComplianceType.COMPLIANT,
            )
        )

        rdklibtest.assert_successful_evaluation(self, response, resp_expected)

    def test_sample_non_compliant(self):
        response = RULE.evaluate_change(
            event=json.dumps(self.invoking_event_iam_role_sample),
            client_factory=CLIENT_FACTORY,
            configuration_item=self.configuration_item,
            valid_rule_parameters=RULE.evaluate_parameters(self.rule_parameters_non_compliant),
        )

        resp_expected = []
        resp_expected.append(
            Evaluation(
                complianceType=ComplianceType.NON_COMPLIANT
            )
        )
        
        rdklibtest.assert_successful_evaluation(self, response, resp_expected)
        