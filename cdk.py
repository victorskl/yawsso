import os

from aws_cdk import Environment, Stack, App
from aws_cdk import aws_ec2 as ec2
from constructs import Construct

# https://docs.aws.amazon.com/cdk/latest/guide/environments.html
env_profile = Environment(
    account=os.environ.get('CDK_DEPLOY_ACCOUNT', os.environ['CDK_DEFAULT_ACCOUNT']),
    region=os.environ.get('CDK_DEPLOY_REGION', os.environ['CDK_DEFAULT_REGION'])
)


class DebugStack(Stack):
    def __init__(self, scope: Construct, id_: str, props, **kwargs) -> None:
        super().__init__(scope, id_, **kwargs)

        vpc = ec2.Vpc.from_lookup(self, "VPC", is_default=True)
        print(f">>> vpc_id: {vpc.vpc_id}")

        print(">>> vpc.public_subnets: ")
        for subnet in vpc.public_subnets:
            print(subnet.subnet_id)


class DebugApp(App):
    def __init__(self):
        super().__init__()
        DebugStack(self, "debug-stack", props={}, env=env_profile)


if __name__ == '__main__':
    DebugApp().synth()

# Usage:
#   aws sso login --profile dev
#   yawsso -p dev
#   cdk synth --app "python cdk.py" --profile dev
#   cdk context -j | jq
