from setuptools import setup, find_packages

setup(
    name='LordofTheBrines',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        'numpy>=1.20.0',
        'requests>=2.25.0',
        'matplotlib>=3.3.0',
    ],
    entry_points={
        'console_scripts': [
            'lordofthebrines=main:main',
        ],
    },
)


