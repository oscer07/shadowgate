"""ShadowGate package setup."""

from setuptools import setup, find_packages
from pathlib import Path

long_description = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

setup(
    name="shadowgate",
    version="1.0.0",
    description="Private Proxy Server & Honeypot Toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="ShadowGate Contributors",
    license="MIT",
    url="https://github.com/shadowgate-project/shadowgate",
    packages=find_packages(exclude=["tests*"]),
    include_package_data=True,
    package_data={
        "shadowgate": ["dashboard/templates/*", "dashboard/static/*"],
    },
    python_requires=">=3.10",
    install_requires=[
        "aiohttp>=3.9.0",
        "flask>=3.0.0",
        "click>=8.1.0",
        "PyYAML>=6.0.1",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.23.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "mypy>=1.7.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "shadowgate=shadowgate.__main__:cli",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: Proxy Servers",
    ],
)
