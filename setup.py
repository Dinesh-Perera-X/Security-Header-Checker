from setuptools import setup, find_packages

setup(
    name="security-header-checker",
    version="1.0.0",
    description="A lightweight CLI tool to audit HTTP security headers and generate assessment reports.",
    author="Dinesh Perera",
    url="https://github.com/Dinesh-Perera-X/Security-Header-Checker",
    py_modules=["header_checker"],
    install_requires=[
        "requests>=2.25.0",
        "urllib3>=1.26.0"
    ],
    entry_points={
        "console_scripts": [
            "header-checker=header_checker:main",
        ],
    },
    python_requires=">=3.6",
)
