from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="vulnscope",
    version="0.1.0",
    description="VulnScope - Fast, modular vulnerability assessment CLI tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Your Name",
    url="https://github.com/yourusername/vulnscope",
    license="MIT",
    packages=find_packages(exclude=("tests",)),
    python_requires=">=3.8",
    install_requires=[
        "colorama>=0.4.6",
        "tqdm>=4.66.0",
        "requests>=2.32.0",
    ],
    entry_points={
        "console_scripts": [
            "vulnscope = vulnscope.main:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Environment :: Console",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
)
