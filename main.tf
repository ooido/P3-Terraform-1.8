provider "aws" {
    region = local.region
  
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", module.eks.cluster_id]
  }
}

locals {
    cluster_name = "ben-project-3-sre"
    region = "us-east-1"
}

data "aws_caller_identity" "current" {}



############
# EKS MODULE
############

module "eks" {
  source = "terraform-aws-modules/eks/aws"
  version = "18.26.2"

  cluster_name = local.cluster_name
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access = true

    cluster_addons = {
    coredns = {
      resolve_conflicts = "OVERWRITE"
    }
    kube-proxy = {}
    vpc-cni = {
      resolve_conflicts = "OVERWRITE"
    }
  }
  
  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.intra_subnets

  # Extend cluster security group rules
  cluster_security_group_additional_rules = {
    egress_nodes_ephemeral_ports_tcp = {
      description                = "To node 1025-65535"
      protocol                   = "tcp"
      from_port                  = 1025
      to_port                    = 65535
      type                       = "egress"
      source_node_security_group = true
    }
  }

  # Extend node-to-node security group rules
  node_security_group_ntp_ipv4_cidr_block = ["169.254.169.123/32"]
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
    egress_all = {
      description      = "Node all egress"
      protocol         = "-1"
      from_port        = 0
      to_port          = 0
      type             = "egress"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
    }
  }

   # EKS Managed Node Group(s)
  eks_managed_node_group_defaults = {
    ami_type       = "AL2_x86_64"
    instance_types = ["t3.micro"]

    attach_cluster_primary_security_group = true
    vpc_security_group_ids                = [aws_security_group.additional.id]
  }

  eks_managed_node_groups = {
    blue = {}
    green = {
      min_size     = 2
      max_size     = 6
      desired_size = 3

      instance_types = ["t3.micro"]
      capacity_type  = "ON_DEMAND"

      update_config = {
        max_unavailable_percentage = 50 # or set `max_unavailable`
      }
    }
  }

  #Auth Config
  manage_aws_auth_configmap = true

  aws_auth_users = [
    {
      userarn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/kube"
      username = "kube"
      groups   = ["system:masters"]
    },
  ]
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 3.0"

  name = local.cluster_name
  cidr = "10.0.0.0/16"

  azs             = ["${local.region}a", "${local.region}b", "${local.region}c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
  intra_subnets   = ["10.0.7.0/28", "10.0.7.16/28", "10.0.7.32/28"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  enable_flow_log                      = true
  create_flow_log_cloudwatch_iam_role  = true
  create_flow_log_cloudwatch_log_group = true

  public_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/elb"              = 1
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"     = 1
  }
}

resource "aws_security_group" "additional" {
  name_prefix = "${local.cluster_name}-additional"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

    ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

    ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_iam_user" "kube" {
    name = "kube"
    path = "/system/"
}

resource "aws_iam_access_key" "kube" {
    user = aws_iam_user.kube.name
}

resource "aws_iam_user_policy" "kubernetes-access" {
    depends_on = [
      module.eks
    ]
    name= "access"
    user = aws_iam_user.kube.name

    policy = jsonencode({    
        "Version": "2012-10-17",
        "Statement":[ 
            {
                "Sid":"VisualEditor0",
                "Effect":"Allow",
                "Action":[
                "eks:AccessKubernetesApi",
                "eks:DescribeCluster",
                "eks:ListClusters"],
                "Resource":"${module.eks.cluster_arn}"
            }
        ]
    })
}