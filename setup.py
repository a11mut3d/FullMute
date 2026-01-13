from setuptools import setup, find_packages

setup(
    name="fullmute",
    version="1.0.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "aiohttp>=3.9.0",
        "PyYAML>=6.0",
        "aiosqlite>=0.19.0",
        "rich>=13.7.0",
        "fake-useragent>=1.4.0",
        "psutil>=5.9.0",
        "sqlalchemy>=2.0.0",
        "requests>=2.31.0",
    ],
    entry_points={
        "console_scripts": [
            "fullmute=fullmute.main:entrypoint",
        ],
    },
    python_requires=">=3.8",
    include_package_data=True,
    package_data={
        "fullmute": ["config/signatures/*.json"],
    },
    author="a11mut3d",
    description="Mass web scanner with technology detection and sensitive file finder",
    keywords="security scanner web technology detection",
)
