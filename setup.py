from setuptools import setup

setup(
    name="ca-bee",
    version="2.1.0",
    py_modules=["ca_bee"],
    install_requires=["urllib3", "requests"],
    entry_points="""
        [console_scripts]
        ca=ca_bee:ca_main
        cai=ca_bee:cai_main
        ca-update=ca_bee:ca_update_main
        ca-login=ca_bee:ca_login_main
    """,
)