from guardduty_soar.schemas import (
    BaseResourceDetails,
    EC2InstanceDetails,
    map_resource_to_model,
)


def test_map_resource_to_model_for_ec2_instance(guardduty_finding_detail):
    """
    Tests that a standard EC2 finding is correctly mapped to the EC2InstanceDetails model.
    """
    resource_data = guardduty_finding_detail["Resource"]

    model = map_resource_to_model(resource_data)

    assert isinstance(model, EC2InstanceDetails)
    assert model.resource_type == "Instance"
    assert model.instance_id == "i-99999999"
    assert model.public_ip is None


def test_map_resource_to_model_for_enriched_ec2_instance(enriched_ec2_finding):
    """
    Tests that an enriched EC2 finding correctly populates the model
    using both the finding data and the instance metadata.
    """
    resource_data = enriched_ec2_finding["guardduty_finding"]["Resource"]
    metadata = enriched_ec2_finding["instance_metadata"]

    model = map_resource_to_model(resource_data, instance_metadata=metadata)

    assert isinstance(model, EC2InstanceDetails)
    assert model.instance_id == "i-99999999"
    assert model.public_ip == "198.51.100.1"
    assert model.vpc_id == "vpc-12345678"
    assert (
        model.iam_profile_arn
        == "arn:aws:iam::1234567891234:instance-profile/EC2-Web-Role"
    )
    assert model.tags[0]["Key"] == "Name"


def test_map_resource_to_model_fallback(s3_finding_detail):
    """
    Tests that a finding with an un-mapped resource type gracefully falls back
    to the BaseResourceDetails model.
    """
    resource_data = s3_finding_detail["Resource"]
    model = map_resource_to_model(resource_data)

    assert isinstance(model, BaseResourceDetails)
    assert not isinstance(model, EC2InstanceDetails)
    assert model.resource_type == "S3Bucket"
