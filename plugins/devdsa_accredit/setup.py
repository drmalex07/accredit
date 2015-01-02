from setuptools import setup, find_packages
import sys, os

version = '0.3'

setup(name='devdsa_accredit',
      version=version,
      description="devdsa accredit-related libraries",
      long_description="""\
""",
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='',
      author='Michail Alexakis',
      author_email='drmalex07@gmail.com',
      url='',
      license='GPLv3',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          # -*- Extra requirements: -*-
          "accredit>=0.4.0",
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
