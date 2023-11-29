from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType, InvalidParametersError
import json
import urllib

APPLICABLE_RESOURCES = ['AWS::IAM::Role']

class githubActionsTrustChecker(ConfigRule):
    def evaluate_change(self, event, client_factory, configuration_item, valid_rule_parameters):
        result = ComplianceType.NOT_APPLICABLE
        trust_claim_subject = valid_rule_parameters

        # Trust policy JSON is stored in a single field, need to unquote and load as JSON
        trustPolicy = json.loads(urllib.parse.unquote(configuration_item['configuration']['assumeRolePolicyDocument']))
        statements = trustPolicy['Statement']
        
        # IAM policy language allows either a single statement, or an array of statements.
        # Normalise to a list for code readability
        if not isinstance(statements, list):
            statements = [statements]
            
        # Check each statement within the trust policy for the GitHub Actions OIDC provider
        # If found - default to a non-compliant result
        # Only return compliant if:
        #   1. A trust claim subject string has been supplied as a parameter and is contained within
        #      the subject condition statement of the IAM trust policy.
        #   2. No trust claim subject was supplied as a parameter, but a subject condition as used
        # 
        # This evaluation logic is provided as an example, but should be extended as required to
        # support the business logic required to validate the subjects that can assume a role.
        # For example, by looking up a known list of trusted GitHub Organizations and repositories,
        # and validating that the job was run from a workflow referencing an environment called
        # "Production".
        for statement in statements:
            if str(statement.get('Principal').get('Federated')).endswith('oidc-provider/token.actions.githubusercontent.com') \
                and str(statement['Action']) == 'sts:AssumeRoleWithWebIdentity':
                    result = ComplianceType.NON_COMPLIANT
                    for condition in statement['Condition'].items():
                        # Build your own logic here to validate trusted subjects that can assume an IAM role
                        # See https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#example-subject-claims
                        # for a list of example subject claims that can be used
                        if 'token.actions.githubusercontent.com:sub' in str(condition):
                            if trust_claim_subject != None:
                                if trust_claim_subject in str(condition):
                                    result = ComplianceType.COMPLIANT

        return [Evaluation(result)]

    def evaluate_parameters(self, rule_parameters):
        if not rule_parameters:
                return {}

        if len(rule_parameters) > 1:
            raise InvalidParametersError(str('The parameter (' + str(rule_parameters) + ') has more than one key. The only accepted key is: TrustClaimSubject.'))
        elif len(rule_parameters) == 1 and "TrustClaimSubject" not in rule_parameters:
            raise InvalidParametersError('The parameter (' + str(rule_parameters) + ') has not a valid key.')

        trust_claim_subject = rule_parameters['TrustClaimSubject'].replace(' ','')
        return trust_claim_subject
        
    def get_assume_role_mode(self, event):
        return False


################################
# DO NOT MODIFY ANYTHING BELOW #
################################
def lambda_handler(event, context):
    my_rule = githubActionsTrustChecker()
    evaluator = Evaluator(my_rule, APPLICABLE_RESOURCES)
    return evaluator.handle(event, context)
