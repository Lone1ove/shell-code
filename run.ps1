param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

# Clear foreign virtualenv hints so `uv run` uses this project's `.venv` cleanly.
if (Test-Path Env:VIRTUAL_ENV) {
    Remove-Item Env:VIRTUAL_ENV -ErrorAction SilentlyContinue
}
if (Test-Path Env:CONDA_PREFIX) {
    Remove-Item Env:CONDA_PREFIX -ErrorAction SilentlyContinue
}

& uv run @Args
exit $LASTEXITCODE
