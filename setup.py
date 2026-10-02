from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as readme_file:
    long_description = readme_file.read()

setup(
    name="emr00t-toolkit",
    version="0.1.0",
    author="emR00T",
    description="Offensive security toolkit: recon, web, crypto, payload, network",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/emR00T/emR00T-toolkit",
    packages=find_packages(exclude=["tests*", "docs*"]),
    python_requires=">=3.10",
    install_requires=[
        "requests>=2.31.0",
        "dnspython>=2.4.0",
        "cryptography>=41.0.0",
    ],
    extras_require={
        "full": [
            "colorama>=0.4.6",
            "beautifulsoup4>=4.12.0",
            "lxml>=4.9.0",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    entry_points={
        "console_scripts": [],
    },
)
