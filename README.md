# spf-validator

spf-validator is a Python package for validating Sender Policy Framework strings and records to ensure they are formatted correctly.

The validation returns a list of strings where each string, if any, is an issue with the SPF record.

## Installation

Use pip to install:

```python
pip install spf-validator
```

## Usage

There are two main functions in the package: `validate_spf_string` and `validate_domain_spf`. Both of these will return a list of strings where each string, if any, is an issue with the SPF record.

To validate an SPF string, use `validate_spf_string` by passing it the string.

To use:

```python
from spf_validator import validator

issues_list = validator.validate_spf_string('v=spf1 a mx include:_spf.google.com ~all')
```

To validate an SPF record on a given domain, use `validate_domain_spf` by passing it the domain. This will retrieve the TXT records for the domain, locate the SPF record, and validate it.

To use:

```python
from spf_validator import validator

issues_list = validator.validate_domain_spf('google.com')
```

## Contributing

Community made feature requests, patches, bug reports, and contributions are always welcome.

Please review [our contributing guidelines](https://github.com/fpcorso/spf-validator/blob/main/CONTRIBUTING.md) if you decide to make a contribution.

## License

This project is licensed under the MIT License. See [LICENSE](https://github.com/fpcorso/spf-validator/blob/main/LICENSE) for more details.