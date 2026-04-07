# GRC Automation Framework

## Purpose
The capstone project — a professional Python package that unifies all previous tools into a single, organized framework. Demonstrates proper package structure, `__init__.py`, shared configuration, CLI entry points, and unit testing with pytest.

## Package Structure
```
grc_framework/
├── __init__.py              # Package version and exports
├── __main__.py              # CLI entry point (python -m grc_framework)
├── config.py                # Shared configuration (dataclass, singleton)
├── core/                    # Core utilities
│   ├── __init__.py
│   └── utils.py             # Logging, JSON, timestamps, progress
├── scanners/                # AWS/resource scanners
│   ├── __init__.py
│   └── aws_scanner.py       # S3, IAM scanners with findings
├── reports/                 # Report generation
│   ├── __init__.py
│   └── generator.py         # JSON, Markdown, executive summary
├── risk/                    # Risk register integration
│   ├── __init__.py
│   └── register.py          # Database abstraction
└── tests/                   # Unit tests
    ├── __init__.py
    └── test_framework.py    # pytest test suite
```

## How to Run
```bash
pip install pytest

python -m grc_framework version
python -m grc_framework config
python -m grc_framework audit iam
python -m grc_framework report compliance --markdown

# Run tests
cd grc_framework
python -m pytest tests/ -v
```

## CLI Commands
| Command | Description |
|---------|-------------|
| `version` | Show version info |
| `config` | Display current configuration |
| `audit <target>` | Run compliance audit (iam, s3, cloudtrail, all) |
| `scan <resource>` | Scan resources (s3, cloudtrail, drift, cfn) |
| `report <type>` | Generate report (compliance, risk, executive) |
| `risk <operation>` | Risk register ops (list, add, update, summary) |
| `alert` | Send test alert |
| `dashboard` | Start web dashboard |

## Configuration
Set via environment variables:
```bash
export GRC_AWS_PROFILE="your-profile"
export GRC_AWS_REGION="us-east-1"
export GRC_OUTPUT_DIR="./reports"
export GRC_SLACK_WEBHOOK="https://hooks.slack.com/..."
export GRC_LOG_LEVEL="INFO"
```

## Python Concepts Demonstrated

### Package Structure
- **`__init__.py`** — Marks directory as Python package
- **`__main__.py`** — Enables `python -m package` execution
- **`__version__`** — Single source of truth for version

### Design Patterns
- **Dataclass** — `GRCConfig` with auto-generated `__init__`, `__repr__`
- **Singleton** — Global config instance via `get_config()`
- **Template Method** — `AWSScanner.scan()` base class pattern
- **Context Manager** — `ProgressTracker` with `__enter__/__exit__`
- **Fluent Interface** — `ReportGenerator.add_findings().generate_json()`
- **Strategy Pattern** — Multiple report formats (JSON, Markdown)

### Testing
- **pytest fixtures** — `temp_config`, `sample_findings`
- **Parameterized tests** — Run same test with different data
- **Mocking** — `unittest.mock.Mock`, `monkeypatch`
- **Fixtures scope** — Setup/teardown per test
- **Assertions** — `assert`, `pytest.raises()`

### Advanced Features
- **Type hints** — `-> List[Finding]`, `Optional[str]`
- **f-strings** — Modern string formatting
- **Pathlib** — Modern path handling
- **Dataclasses** — `asdict()` for serialization
- **Hierarchical imports** — `from ..config import get_config`

## Key Classes

### `GRCConfig` (dataclass)
```python
config = GRCConfig.from_env()
print(config.aws_profile)  # "grcengtest-1"
```

### `Finding` (dataclass)
```python
finding = Finding(
    resource_type="S3",
    resource_id="bucket-1",
    finding_type="No Encryption",
    severity="HIGH",
    description="...",
    control="SC-28",
    remediation="Enable encryption"
)
print(finding.to_dict())  # JSON-serializable
```

### `AWSScanner` (abstract base)
```python
with S3Scanner(profile="grcengtest-1") as scanner:
    findings = scanner.scan()
```

### `ReportGenerator`
```python
gen = ReportGenerator(findings)
gen.generate_json()      # JSON report
gen.generate_markdown()  # Markdown report
print(gen.generate_executive_summary())
```

## Test Coverage
| Module | Tests |
|--------|-------|
| Config | Version, env loading, defaults |
| Utils | Timestamps, sanitization, JSON, progress |
| Scanners | Finding creation, mock mode scanning |
| Reports | JSON/Markdown generation, summaries |
| Integration | End-to-end workflow |

## Output
- Reports saved to `GRC_OUTPUT_DIR` (default: `~/grc_reports`)
- Logs written to `grc_framework.log`
- JSON and Markdown reports with timestamps

## Architecture
This capstone ties together the individual tools:
- `scanners/` — S3 and IAM scanning modules
- `reports/` — JSON and Markdown report generation
- `risk/` — Risk register database abstraction
- CLI — Alert integration and dashboard launcher
