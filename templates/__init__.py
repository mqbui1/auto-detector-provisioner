from .apm import APMTemplates
from .jvm import JVMTemplates
from .kubernetes import KubernetesTemplates
from .kafka import KafkaTemplates
from .redis import RedisTemplates
from .database import DatabaseTemplates
from .aws import AWSTemplates
from .dotnet import DotNetTemplates
from .nodejs import NodeJSTemplates

# Registry: detected technology → template class
TEMPLATE_REGISTRY: dict[str, type] = {
    "jvm":          JVMTemplates,
    "spring_boot":  JVMTemplates,
    "dotnet":       DotNetTemplates,
    "nodejs":       NodeJSTemplates,
    "kafka":        KafkaTemplates,
    "redis":        RedisTemplates,
    "postgresql":   DatabaseTemplates,
    "mysql":        DatabaseTemplates,
    "mongodb":      DatabaseTemplates,
    "kubernetes":   KubernetesTemplates,
    "aws_ec2":      AWSTemplates,
    "aws_rds":      AWSTemplates,
    "aws_lambda":   AWSTemplates,
    "aws_ecs":      AWSTemplates,
    "aws_sqs":      AWSTemplates,
}
