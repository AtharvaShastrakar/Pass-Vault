from setuptools import setup, find_packages

setup(
    name="passvault",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "argon2-cffi>=21.3.0",
        "cryptography>=41.0.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "pv = passvault.cli:main",
        ],
    },
)
