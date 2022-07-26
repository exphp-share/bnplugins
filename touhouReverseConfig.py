import binaryninja as bn
from binaryninja import log
import typing as tp
import os
import toml
import copy
from dataclasses import dataclass
from pathlib import Path

CONFIG_PATH = Path(__file__).with_name('touhouReverse.toml')

@dataclass
class Config:
    bndb_dir: Path
    mapfile_dir: Path

    @classmethod
    def read_system(cls):
        if not CONFIG_PATH.is_file():
            config = copy.deepcopy(DEFAULT_CONFIG)
            config.write(CONFIG_PATH)

        return cls.read(CONFIG_PATH)

    @classmethod
    def read(cls, path):
        with open(path) as f:
            d = toml.load(open(path))
        general = d.pop('general')
        out = cls(
            bndb_dir=Path(general.pop('bndb-dir')),
            mapfile_dir=Path(general.pop('mapfile-dir')),
        )
        for key in d:
            log.log_warn(f"Unexpected config key '{key}'.  Did you forget to write '[general]'?")
        for key in general:
            log.log_warn(f"Unexpected config key 'general.{key}'")
        return out

    def write(self, path):
        d = {'general': {
            'bndb-dir': str(self.bndb_dir),
            'mapfile-dir': str(self.mapfile_dir),
        }}
        with open(path, 'w') as f:
            toml.dump(d, f)

DEFAULT_CONFIG = Config(
    bndb_dir = r"E:\Downloaded Software\Touhou Project",
    mapfile_dir = r'F:\asd\clone\ecl-parse\map',
)
