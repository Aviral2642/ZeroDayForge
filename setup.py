from setuptools import setup, find_packages

with open("README.md", "r") as fh:
	long_description = fh.read()

setup(
	name="zerodayforge",
	version="1.0.0",
	author="Aviral Srivastava",
	author_email="aviralyash27@gmail.com",
	description="Advanced Exploitation Framework",
	long_description=long_description,
	long_description_content_type="text/markdown",
	url="https://github.com/Aviral2642/zerodayforge",
	packages=find_packages(),
	include_package_data=True,
	package_data={
		'zerodayforge': [
			'config/*.json',
			'examples/*.*',
			'scripts/*.sh'
		]
	},
	install_requires=[
		'impacket>=0.11.0',
		'keystone-engine>=0.9.2',
		'capstone>=5.0.0',
		'pycryptodomex>=3.19.0',
		'psutil>=5.9.0',
		'scapy>=2.5.0',
		'dnslib>=0.9.23',
		'pyrdp>=1.0.0',
		'argparse>=1.4.0'
	],
	entry_points={
		'console_scripts': [
			'zerodayforge=zerodayforge.ZeroDayForge:main'
		]
	},
	classifiers=[
		"Programming Language :: Python :: 3",
		"License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
		"Operating System :: POSIX :: Linux",
		"Operating System :: Microsoft :: Windows",
		"Environment :: Console"
	],
	python_requires='>=3.8',
)