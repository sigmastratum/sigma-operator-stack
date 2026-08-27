#!/usr/bin/env python3
"""Build the exact Windows private-alpha PE bootstrap with pinned Go."""
import argparse, hashlib, io, json, os, subprocess, tarfile, tempfile
from pathlib import Path
GO_VERSION = "go1.27.0"
def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--repository",type=Path,required=True); parser.add_argument("--candidate",required=True); parser.add_argument("--go",type=Path,required=True); parser.add_argument("--output",type=Path,required=True); args=parser.parse_args()
    repository=args.repository.resolve(strict=True); candidate=subprocess.run(["git","-C",os.fspath(repository),"rev-parse","--verify",f"{args.candidate}^{{commit}}"],check=True,stdout=subprocess.PIPE,text=True).stdout.strip()
    head=subprocess.run(["git","-C",os.fspath(repository),"rev-parse","--verify","HEAD^{commit}"],check=True,stdout=subprocess.PIPE,text=True).stdout.strip()
    if head != candidate: raise SystemExit("candidate does not match repository HEAD")
    dirty=subprocess.run(["git","-C",os.fspath(repository),"status","--porcelain=v1","--untracked-files=all"],check=True,stdout=subprocess.PIPE,text=True).stdout
    if dirty: raise SystemExit("repository worktree is not clean")
    tree=subprocess.run(["git","-C",os.fspath(repository),"rev-parse","--verify",f"{candidate}^{{tree}}"],check=True,stdout=subprocess.PIPE,text=True).stdout.strip()
    version=subprocess.run([os.fspath(args.go),"version"],check=True,stdout=subprocess.PIPE,text=True).stdout.strip()
    if not version.startswith(f"go version {GO_VERSION} "): raise SystemExit("pinned Go toolchain mismatch")
    output=args.output.resolve(); output.parent.mkdir(parents=True,exist_ok=True)
    environment={"CGO_ENABLED":"0","GO111MODULE":"on","GOARCH":"amd64","GOCACHE":os.fspath(output.parent/".gocache"),"GOENV":"off","GOOS":"windows","GOPATH":os.fspath(output.parent/".gopath"),"HOME":os.fspath(output.parent/".home"),"LANG":"C.UTF-8","LC_ALL":"C.UTF-8","PATH":os.environ.get("PATH",""),"TZ":"UTC"}
    archive=subprocess.run(["git","-C",os.fspath(repository),"archive","--format=tar",candidate,"--","installers/windows-installer"],check=True,stdout=subprocess.PIPE).stdout
    with tempfile.TemporaryDirectory(prefix="sos-windows-installer-source-") as temporary:
        source_root=Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(archive),mode="r:") as bundle:
            bundle.extractall(source_root,filter="data")
        subprocess.run([os.fspath(args.go),"build","-buildvcs=false","-trimpath","-ldflags",f"-buildid= -s -w -X main.candidate={candidate}","-o",os.fspath(output),"."],cwd=source_root/"installers"/"windows-installer",env=environment,check=True,stdin=subprocess.DEVNULL)
    payload=output.read_bytes(); digest=hashlib.sha256(payload).hexdigest()
    if payload[:2]!=b"MZ" or len(payload)>8*1024*1024: raise SystemExit("output is not one bounded PE executable")
    print(json.dumps({"candidate":candidate,"filename":output.name,"go_version":GO_VERSION,"sha256":digest,"source_tree":tree,"status":"passed"},sort_keys=True,separators=(",",":"))); return 0
if __name__=="__main__": raise SystemExit(main())
