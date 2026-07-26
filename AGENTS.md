## Documentation and Specification
During implementation, keep track of API changes and keep the README.md updated.
README should be clear and concise. No long yap when few words work.

## Security Rules
- Never read, reference, or parse files matching *.env or *.pem.
- Instead, use .env.example or .pem.example files to provide placeholder values for secrets, tokens, and connection strings.
- Treat all configuration values as placeholders.
- Never output real secrets, tokens, or connection strings.