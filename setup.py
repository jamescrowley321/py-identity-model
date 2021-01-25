from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

install_requires = ["python-jose", "requests"]

test_require = ["python-jose", "requests", "pytest"]

setup(
    name="py_identity_model",
    version="0.8.1",
    description="OIDC helper library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jamescrowley321/py-oidc",
    author="James Crowley",
    author_email="jamescrowley151@gmail.com",
    license="Apache 2.0",
    platforms="Any",
    install_requires=install_requires,
    extras_require={"test": test_require},
    keywords="OpenID jwt",
    packages=["py_identity_model"],
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.7",
        "Operating System :: OS Independent",
    ],
    zip_safe=False,
)
