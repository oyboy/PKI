from setuptools import setup, find_packages

setup(
    name="micropki",
    version="1.0.0",
    description="MicroPKI - A minimal Public Key Infrastructure",
    author="Student",
    packages=find_packages(),
    install_requires=[
        "cryptography>=3.0",
    ],
    entry_points={
        "console_scripts": [
            "micropki=micropki.cli:main",
        ],
    },
    python_requires=">=3.8",
)