#!/usr/bin/env python3
"""Run public tests and stage private tests without widening library APIs."""
import argparse
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(command, cwd):
    child = subprocess.Popen(command, cwd=cwd, start_new_session=True)
    try:
        code = child.wait(timeout=300)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        raise
    if code:
        raise subprocess.CalledProcessError(code, command)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--odin', default=os.environ.get('ODIN', 'odin'))
    parser.add_argument('--package', default='all')
    parser.add_argument('--internal-only', action='store_true')
    parser.add_argument('flags', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    flags = args.flags[1:] if args.flags[:1] == ['--'] else args.flags
    suites = []
    for directory in sorted({p.parent for p in ROOT.rglob('*_test.odin')
                             if '.git' not in p.parts}):
        relative = directory.relative_to(ROOT)
        private = relative.parts[-2:] == ('tests', 'internal')
        package = relative.parent.parent if private else relative.parent
        if args.package != 'all' and str(package) != args.package:
            continue
        if not args.internal_only or private:
            suites.append((relative, private))
    if not suites:
        parser.error('no matching test suites')
    with tempfile.TemporaryDirectory(prefix='odin-library-tests-') as temporary:
        shared = Path(temporary) / 'shared'
        shared.mkdir()
        staged = shared / ROOT.name
        for source_root in ROOT.parent.iterdir():
            if not source_root.is_dir() or not (source_root / '.git').exists():
                continue
            if source_root.name == 'metalized' and source_root != ROOT:
                continue
            names = subprocess.check_output([
                'git', '-C', str(source_root), 'ls-files', '--cached', '--others',
                '--exclude-standard', '-z']).decode().split('\0')
            for name in filter(None, names):
                source = source_root / name
                if not source.is_file():
                    continue
                destination = shared / source_root.name / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
        if not any(f.startswith('-collection:shared=') for f in flags):
            flags = ['-collection:shared=' + str(shared), *flags]
        for relative, private in suites:
            target = staged / relative
            if private:
                target = target.parent.parent
                for source in (staged / relative).glob('*.odin'):
                    shutil.copy2(source, target / source.name)
            output = [] if any(f.startswith('-out:') for f in flags) else [
                '-out:' + str(Path(temporary) / 'tests')]
            print(f'Testing {relative}', flush=True)
            run([args.odin, 'test', str(target), *output, *flags], shared)


if __name__ == '__main__':
    main()
