import pytest

from guardduty_soar.schemas import (
    AccessKeyDetails,
    BaseResourceDetails,
    EC2InstanceDetails,
    EKSClusterDetails,
    LambdaDetails,
    RDSInstanceDetails,
    S3BucketDetails,
    map_resource_to_model,
)

# --- Fixtures for different GuardDuty Resource types ---


@pytest.fixture
def ec2_resource_data():
    return {"ResourceType": "Instance", "InstanceDetails": {"InstanceId": "i-12345"}}


@pytest.fixture
def access_key_resource_data():
    return {"ResourceType": "AccessKey", "AccessKeyDetails": {"UserName": "test-user"}}


@pytest.fixture
def s3_bucket_resource_data():
    return {"ResourceType": "S3Bucket", "S3BucketDetails": [{"Name": "my-test-bucket"}]}


@pytest.fixture
def eks_cluster_resource_data():
    return {
        "ResourceType": "EKSCluster",
        "EksClusterDetails": {"Name": "my-eks-cluster"},
    }


@pytest.fixture
def rds_instance_resource_data():
    return {
        "ResourceType": "DBInstance",
        "RdsDbInstanceDetails": {"DbInstanceIdentifier": "my-db"},
    }


@pytest.fixture
def lambda_resource_data():
    return {"ResourceType": "Lambda", "LambdaDetails": {"FunctionName": "my-lambda"}}


@pytest.fixture
def unknown_resource_data():
    return {"ResourceType": "SomeNewService", "SomeNewServiceDetails": {"Id": "new-id"}}


# --- Test Functions for the Mapper ---


def test_map_ec2_instance(ec2_resource_data):
    """Tests mapping for EC2 Instance resource type."""
    model = map_resource_to_model(ec2_resource_data)
    assert isinstance(model, EC2InstanceDetails)
    assert model.instance_id == "i-12345"


def test_map_access_key(access_key_resource_data):
    """Tests mapping for AccessKey resource type."""
    model = map_resource_to_model(access_key_resource_data)
    assert isinstance(model, AccessKeyDetails)
    assert model.user_name == "test-user"


def test_map_s3_bucket(s3_bucket_resource_data):
    """Tests mapping for S3Bucket resource type."""
    model = map_resource_to_model(s3_bucket_resource_data)
    assert isinstance(model, S3BucketDetails)
    assert model.bucket_name == "my-test-bucket"


def test_map_eks_cluster(eks_cluster_resource_data):
    """Tests mapping for EKSCluster resource type."""
    model = map_resource_to_model(eks_cluster_resource_data)
    assert isinstance(model, EKSClusterDetails)
    assert model.cluster_name == "my-eks-cluster"


def test_map_rds_instance(rds_instance_resource_data):
    """Tests mapping for RDS DBInstance resource type."""
    model = map_resource_to_model(rds_instance_resource_data)
    assert isinstance(model, RDSInstanceDetails)
    assert model.db_instance_identifier == "my-db"


def test_map_lambda_function(lambda_resource_data):
    """Tests mapping for Lambda resource type."""
    model = map_resource_to_model(lambda_resource_data)
    assert isinstance(model, LambdaDetails)
    assert model.function_name == "my-lambda"


def test_map_unknown_resource_fallback(unknown_resource_data):
    """Tests that an unknown resource type gracefully falls back to the base model."""
    model = map_resource_to_model(unknown_resource_data)
    assert isinstance(model, BaseResourceDetails)
    assert not isinstance(
        model, EC2InstanceDetails
    )  # Ensure it's not a more specific type
    assert model.resource_type == "SomeNewService"
