import argparse
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
SA = os.path.join(ROOT, "static_analysis")
IMAGE = "llmfuzz"
MXML = "https://github.com/michaelrsweet/mxml"


def run(cmd, **kw):
    print("$", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True, **kw)


def docker_up():
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def is_wsl():
    try:
        with open("/proc/version") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def docker_hint():
    if is_wsl():
        return ("docker isn't running. Start Docker Desktop on Windows and turn on WSL integration for this distro\n"
                "(Docker Desktop > Settings > Resources > WSL Integration)")
    if sys.platform.startswith("linux"):
        err = subprocess.run(["docker", "info"], capture_output=True, text=True).stderr.lower()
        if "permission denied" in err:
            return ("docker is running but your user can't use it. Run:\n"
                    "    sudo usermod -aG docker $USER\n"
                    "then close this terminal and open a new one")
        return ("docker isn't running. Start it with:\n"
                "    sudo systemctl start docker\n"
                "(to start it automatically at boot: sudo systemctl enable --now docker)")
    return "docker isn't running. Start Docker Desktop"


def in_docker():
    if not shutil.which("docker"):
        if is_wsl():
            sys.exit("docker not found in WSL. Start Docker Desktop on Windows and turn on WSL integration for this distro\n"
                     "(Docker Desktop > Settings > Resources > WSL Integration)\nthen run ./setup.sh again")
        sys.exit("docker not found, install Docker first")
    if not docker_up() and sys.platform == "darwin":
        print("[*] starting Docker Desktop", flush=True)
        if subprocess.run(["open", "-a", "Docker"]).returncode == 0:
            for _ in range(60):
                if docker_up():
                    break
                time.sleep(2)
    if not docker_up():
        sys.exit(docker_hint() + "\nthen run ./setup.sh again")
    run(["docker", "build", "-t", IMAGE, ROOT])
    user = ["--user", f"{os.getuid()}:{os.getgid()}"] if hasattr(os, "getuid") else []
    cmd = ["docker", "run", "--rm", "-v", f"{ROOT}:/llmfuzz", "-v", "llmfuzz-codeql:/codeql", *user, IMAGE, "python3", "main.py", *sys.argv[1:]]
    print("$", " ".join(cmd), flush=True)
    sys.exit(subprocess.run(cmd).returncode)


def get_target(url, ref):
    name = os.path.basename(url.rstrip("/")).removesuffix(".git")
    path = os.path.join(ROOT, "targets", name)
    if not os.path.isdir(path):
        run(["git", "clone", url, path])
    if not ref:
        run(["git", "-C", path, "fetch", "-q"])
    run(["git", "-C", path, "checkout", "-q", ref or "origin/HEAD"])
    return name + "-" + (ref or "latest").replace("/", "_"), path


def static_analysis(name, path, rerun):
    out = os.path.join(ROOT, "results", name)
    findings = os.path.join(out, "findings.json")
    if os.path.exists(findings) and not rerun:
        print(f"[*] using existing {findings}")
        return findings
    os.makedirs(out, exist_ok=True)
    run([sys.executable, os.path.join(SA, "static_analyzer.py"), "--target", path, "--out", findings,
         "--backend", "both", "--codeql-db", f"/codeql/{name}"])
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target")
    ap.add_argument("--ref")
    ap.add_argument("--rerun", action="store_true")
    ap.add_argument("--sa", action="store_true", help="static analysis only")
    ap.add_argument("--llm", action="store_true", help="LLM stage only (not implemented yet)")
    ap.add_argument("--fuzz", action="store_true", help="fuzzing only (not implemented yet)")
    args = ap.parse_args()
    if not args.target:
        args.target, args.ref = MXML, args.ref or "v2.12"
    if not (args.sa or args.llm or args.fuzz):
        args.sa = args.llm = args.fuzz = True

    if not os.environ.get("LLMFUZZ_CONTAINER"):
        in_docker()
    name, path = get_target(args.target, args.ref)
    if args.sa:
        static_analysis(name, path, args.rerun)
        print(f"[+] static analysis done: results/{name}/findings.json")
    if args.llm:
        print("[*] llm stage: not implemented yet")
    if args.fuzz:
        print("[*] fuzz stage: not implemented yet")


if __name__ == "__main__":
    main()
