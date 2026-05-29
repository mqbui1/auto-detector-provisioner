from .apm import APMTemplates
from .jvm import JVMTemplates
from .go import GoTemplates
from .python_runtime import PythonTemplates
from .rust import RustTemplates
from .kubernetes import KubernetesTemplates
from .kafka import KafkaTemplates
from .redis import RedisTemplates
from .database import DatabaseTemplates
from .aws import AWSTemplates
from .dotnet import DotNetTemplates
from .nodejs import NodeJSTemplates
from .spring_boot import SpringBootTemplates
from .django import DjangoTemplates
from .flask import FlaskTemplates
from .fastapi import FastAPITemplates
from .express import ExpressTemplates
from .grpc import GRPCTemplates
from .graphql import GraphQLTemplates
from .rabbitmq import RabbitMQTemplates
from .elasticsearch import ElasticsearchTemplates
from .cassandra import CassandraTemplates
from .celery import CeleryTemplates
from .nginx import NginxTemplates
from .istio import IstioTemplates
from .host import HostTemplates

# Registry: detected technology → template class
TEMPLATE_REGISTRY: dict[str, type] = {
    # Stacks
    "jvm":           JVMTemplates,
    "dotnet":        DotNetTemplates,
    "nodejs":        NodeJSTemplates,
    "go":            GoTemplates,
    "python":        PythonTemplates,
    "rust":          RustTemplates,
    # Frameworks
    "spring_boot":   SpringBootTemplates,
    "spring":        SpringBootTemplates,
    "aspnetcore":    DotNetTemplates,        # ASP.NET Core — use .NET runtime templates
    "nextjs":        ExpressTemplates,      # Next.js uses same HTTP semantic conventions as Express
    "django":        DjangoTemplates,
    "flask":         FlaskTemplates,
    "fastapi":       FastAPITemplates,
    "express":       ExpressTemplates,
    "grpc":          GRPCTemplates,
    "graphql":       GraphQLTemplates,
    # Messaging / streaming
    "kafka":         KafkaTemplates,
    "rabbitmq":      RabbitMQTemplates,
    "celery":        CeleryTemplates,
    # Datastores
    "redis":         RedisTemplates,
    "postgresql":    DatabaseTemplates,
    "mysql":         DatabaseTemplates,
    "mongodb":       DatabaseTemplates,
    "elasticsearch": ElasticsearchTemplates,
    "cassandra":     CassandraTemplates,
    # Infrastructure
    "kubernetes":    KubernetesTemplates,
    "nginx":         NginxTemplates,
    "istio":         IstioTemplates,
    "host":          HostTemplates,
    # Cloud
    "aws_ec2":       AWSTemplates,
    "aws_rds":       AWSTemplates,
    "aws_lambda":    AWSTemplates,
    "aws_ecs":       AWSTemplates,
    "aws_sqs":       AWSTemplates,
}
