#!/usr/bin/env python3
"""Exercise the worker manifest against an offline Cargo workspace."""
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('worker_recipe', Path(__file__).with_name('build-workers.py'))
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)


class WorkerInputsTest(unittest.TestCase):
    def test_active_path_dependency_and_embedded_file(self):
        cargo = Path(subprocess.check_output(
            ['rustc', '--print', 'sysroot'], text=True).strip()) / 'bin/cargo'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'Cargo.toml').write_text(
                '[workspace]\nresolver="2"\nmembers=["worker","storage","unused"]\n')
            for name in ('worker', 'storage', 'unused'):
                crate = root / name
                (crate / 'src').mkdir(parents=True)
                (crate / 'Cargo.toml').write_text(
                    f'[package]\nname="{name}"\nversion="0.1.0"\nedition="2021"\n')
                (crate / 'src/lib.rs').touch()
            with (root / 'worker/Cargo.toml').open('a') as manifest:
                manifest.write('[dependencies]\nstorage={path="../storage",optional=true}\n'
                               '[features]\nselected=["dep:storage"]\n'
                               '[dev-dependencies]\nunused={path="../unused"}\n')
            (root / 'storage/src/lib.rs').write_text('pub const DATA: &[u8] = include_bytes!("data");')
            data = root / 'storage/src/data'
            data.write_bytes(b'first')
            env = dict(PATH=os.environ['PATH'], CARGO_HOME=str(root / 'cargo'),
                       RUSTC=str(cargo.with_name('rustc')), CARGO_TARGET_DIR=str(root / 'target'),
                       SGX_SDK=str(root / 'sdk'), LIBRARY_PATH=str(root))
            (root / 'sdk/include').mkdir(parents=True)
            (root / 'libsgx_dcap_quoteverify.so').touch()
            subprocess.run([cargo, 'generate-lockfile', '--offline'], cwd=root, env=env, check=True)
            plans = [(root, 'worker', 'selected', ('worker',))]
            with patch.object(recipe, 'worker_plans', return_value=plans):
                before = recipe.sources(cargo, env)
                self.assertIn(str(data), before['files'])
                self.assertNotIn(str(root / 'unused/src/lib.rs'), before['files'])
                data.write_bytes(b'other')
                after = recipe.sources(cargo, env)
            changed = {p for p in before['files'] if before['files'][p] != after['files'][p]}
            self.assertEqual(changed, {str(data)})
            self.assertEqual(before['graphs'], after['graphs'])


if __name__ == '__main__':
    unittest.main()
