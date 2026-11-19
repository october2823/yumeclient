from setuptools import setup
from setuptools.dist import Distribution
from wheel.bdist_wheel import bdist_wheel


class BinaryDistribution(Distribution):
    def has_ext_modules(self):
        return True


class BinaryWheel(bdist_wheel):
    """Platform wheel without a CPython ABI tag.

    The native library is loaded through ctypes and never links against
    libpython, so one ``py3-none-<platform>`` wheel serves every supported
    interpreter (including future 3.x releases) instead of one wheel per
    CPython version.
    """

    def finalize_options(self):
        super().finalize_options()
        self.root_is_pure = False

    def get_tag(self):
        _python, _abi, plat = super().get_tag()
        return "py3", "none", plat


setup(distclass=BinaryDistribution, cmdclass={"bdist_wheel": BinaryWheel})
