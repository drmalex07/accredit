try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

setup(
    name='accredit',
    version='0.6.1',
    description='',
    author='Michail Alexakis',
    author_email='drmalex07@gmail.com',
    license='GPLv3',
    url='',
    install_requires=[
        "Pylons>=1.0",
        "SQLAlchemy>=0.5",
        "Genshi>=0.4",
        "Babel",
        "python-ldap",
        "python-openid>=2.2",
        "repoze.who<=1.9",
        "repoze.who.plugins.ldap",
        "repoze.who.plugins.openid",
        "repoze.who.plugins.digestauth",
        "repoze.who-friendlyform==1.0.8",
        "pyopenssl",
        "enum",
        "bidict",
        "redis==2.4.13",
        "zope.interface",
        "beaker_extensions", # for redis backend in beaker sessions
        "openid-redis", # for redis store backend in OP server
    ],
    setup_requires=["PasteScript>=1.6.3"],
    packages=find_packages(exclude=['ez_setup']),
    include_package_data=True,
    test_suite='nose.collector',
    package_data={'accredit': ['i18n/*/LC_MESSAGES/*.mo']},
    message_extractors={'accredit': [
            ('**.py', 'python', None),
            ('**.html', 'genshi', None),
            ('public/**', 'ignore', None)]},
    zip_safe=False,
    paster_plugins=['PasteScript', 'Pylons'],
    entry_points="""
    [paste.app_factory]
    main = accredit.config.middleware:make_app

    [paste.app_install]
    main = pylons.util:PylonsInstaller

    [paste.filter_factory]
    server_name_filter = accredit.lib.middleware:servername_filter_factory
    """,
)
