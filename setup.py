from setuptools import setup

setup(
    name="ca-bee",
    version="2.0.0",
    py_modules=["ca_bee"],
    install_requires=["urllib3", "requests"],
    entry_points="""
        [console_scripts]
        ca=ca_bee:ca_main
        ca-login=ca_bee:ca_login_main
    """,
)