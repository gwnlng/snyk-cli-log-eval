# snyk-cli-log-eval

This is a Snyk CLI debug log evaluation tool that accepts standard input and outputs a result summary of the scan metadata analysis run in a JSON object output. The scan metadata analysis is captured in the standard error corresponding to line with prefix `analytics.report:2 - [0] Data: `.

## Prerequisite
This tool is only compatible with Snyk Open Source product i.e. specifically `snyk test` log analysis.

- Snyk CLI usage authenticated
- Snyk test CLI command executed with `--all-projects` and `--debug` options

## Example Commands

### Single command piping standard error to eval
```
snyk test --all-projects --debug 2> | python3 </path/to/eval.py>
```

### Capturing redirected standard output, error to a logfile for full analysis
```
snyk test --all-projects --debug > debug.log 2>&1
cat "debug.log" | python3 <path/to/eval.py>
```

## Output
The scan metadata result summary is output in JSON format.

## Output Format

| Property          | Description                          | Sample Values                                              |
|-------------------|--------------------------------------|------------------------------------------------------------|
| scanned_manifests | List of scanned manifests file paths | ["/path/to/scanned_manifest_file"]                         |
| skipped_manifests | List of skipped manifests file paths | ["/path/to/skipped_manifest_file"]                         |
| error_indicator   | Flag indicator of error on scan      | true or false                                              |
| error_message     | Generic error message                | "X/Y manifests encountered error at dependency resolution" |
| status            | Status of scan                       | "success" or "failure"                                     |
| duration_sec      | Duration of scan in seconds          | 11.077                                                     |

### Example Output
```
{
    "scanned_manifests":[
        "/Users/REDACTED/VSCodeProjects/gs-multi-module/complete/pom.xml",
        "/Users/REDACTED/VSCodeProjects/gs-multi-module/complete/application/pom.xml",
        "/Users/REDACTED/VSCodeProjects/gs-multi-module/complete/library/build.gradle",
        "/Users/REDACTED/VSCodeProjects/gs-multi-module/complete/library/pom.xml"
    ],
    "skipped_manifests":[
        "/Users/REDACTED/VSCodeProjects/gs-multi-module/complete/application/build.gradle"
    ],
    "error_indicator":true,
    "error_message":"1/5 manifests encountered error at dependency resolution",
    "status":"failure",
    "duration_sec":11.077
}
```

## Note

Snyk CLI version `1.1297.3` debug analytics returns an invalid metadata JSON object.
This is not evident in earlier versions of Snyk CLI and will be resolved in subsequent Snyk CLI releases.
