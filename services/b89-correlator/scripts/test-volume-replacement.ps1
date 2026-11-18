$ErrorActionPreference = 'Stop'
$moduleRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$volume = 'b89-qa-recovery-' + [guid]::NewGuid().ToString('N')
$mount = "type=volume,src=$volume,dst=/qa"
docker volume create $volume
if ($LASTEXITCODE -ne 0) { throw 'Could not create recovery test volume' }
try {
    docker run --rm --network none --mount "type=bind,src=$moduleRoot,dst=/src,readonly" --mount $mount -w /src golang:1.23 sh -ec 'go test -c ./internal/risk -o /qa/risk.test && mkdir /qa/ledger && chown 65532:65532 /qa/ledger'
    if ($LASTEXITCODE -ne 0) { throw 'Could not build recovery fixture' }
    foreach ($phase in 'write', 'recover') {
        Write-Output "Recovery test phase $phase"
        docker run --rm --network none --read-only --user 65532:65532 --mount $mount -e B89_TEST_RECOVERY_DIR=/qa/ledger -e "B89_TEST_RECOVERY_PHASE=$phase" golang:1.23 /qa/risk.test '-test.run=^TestVolumeReplacement$' '-test.v'
        if ($LASTEXITCODE -ne 0) { throw "Recovery test failed in phase $phase" }
    }
} finally {
    docker volume rm $volume
    if ($LASTEXITCODE -ne 0) { throw "Could not remove test volume $volume" }
}
