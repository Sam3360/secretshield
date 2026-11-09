## GitHub Actions Templates

Want to run SecretShield automatically in your GitHub repositories? Use the official [SecretShield GitHub Actions Templates](https://github.com/Sam3360/secretshield-action).

Choose a workflow based on how often you want to scan:

| Workflow | Trigger |
|---|---|
| [Default](https://github.com/Sam3360/secretshield-action/blob/main/templates/default.yml) | Every push and pull request |
| [Daily](https://github.com/Sam3360/secretshield-action/blob/main/templates/daily.yml) | Every day |
| [Weekly](https://github.com/Sam3360/secretshield-action/blob/main/templates/weekly.yml) | Every Monday |
| [Monthly](https://github.com/Sam3360/secretshield-action/blob/main/templates/monthly.yml) | First day of every month |

### Quick Setup

1. Open the [SecretShield Actions Templates repository](https://github.com/Sam3360/secretshield-action).
2. Select the workflow you want.
3. Copy its contents into `.github/workflows/secretshield.yml` in your repository.
4. Commit and push your changes.

SecretShield will automatically install and scan your repository using GitHub Actions.

You can also use the repository's **Use this template** button to create your own copy of all the available workflows.

[Explore all workflow templates →](https://github.com/Sam3360/secretshield-action)
