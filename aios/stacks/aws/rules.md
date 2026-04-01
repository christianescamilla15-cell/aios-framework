# AWS Stack Rules

## Infrastructure as Code
- Use Terraform or CloudFormation for all infra
- Never create resources manually in console for production
- State files must be remote (S3 + DynamoDB lock)
- Tag all resources with project, environment, owner

## Compute
- ECS Fargate for containerized services (no EC2 management)
- Lambda for event-driven / serverless functions
- Auto-scaling configured for production services

## Database
- RDS for relational (PostgreSQL preferred)
- DynamoDB for key-value / high-throughput
- Automated backups enabled
- Multi-AZ for production

## Networking
- VPC with public/private subnets
- ALB for load balancing
- Security groups: least privilege
- No public DB access

## Security
- IAM roles with least privilege (no admin access)
- Secrets in AWS Secrets Manager or Parameter Store
- Encryption at rest and in transit
- CloudTrail enabled

## Deployment
- Use ECS rolling deploy or Blue/Green
- Health checks on ALB target groups
- CloudWatch logs and alarms
- Rollback on failed health check

## Cost
- Use free tier where possible for dev/staging
- Monitor costs with AWS Budgets
- Right-size instances
- Spot instances for non-critical workloads
