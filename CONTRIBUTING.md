```markdown
# Contributing

Thanks for considering contributing!

- Fork the repo and open a PR against main.
- Add tests for new connectors or behavior.
- If adding a connector:
  - Copy connectors/template.py into a new package under payments_sdk.connectors.<provider>
  - Implement methods in ConnectorBase
  - Add docs with configuration/environment variables required
- Run tests: pytest
```