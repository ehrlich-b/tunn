"""A wheel with its helper is platform-specific, never a pure-Python wheel."""
from pathlib import Path
from setuptools import Distribution, setup


class BinaryDistribution(Distribution):
    def has_ext_modules(self):
        return any((Path(__file__).parent / "src/tunn/_bin").glob("tunn-python-bridge*"))


setup(distclass=BinaryDistribution)
