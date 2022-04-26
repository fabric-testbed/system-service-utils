import setuptools
from fss_utils import __VERSION__

with open("README.md", "r") as fh:
  long_description = fh.read()

with open("requirements.txt", "r") as fh:
  requirements = fh.read()

setuptools.setup(
  name="fabric_fss_utils",
  version=__VERSION__,
  author="Ilya Baldin",
  description="FABRIC System Services Utilities library",
  url="https://github.com/fabric-testbed/system-service-utils",
  long_description="FABRIC System Services Utilities library",
  long_description_content_type="text/plain",
  packages=setuptools.find_packages(),
  include_package_data=True,
  classifiers=[
    "Programming Language :: Python :: 3",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
  ],
  python_requires=">=3.9",
  install_requires=requirements,
  setup_requires=requirements,
)
