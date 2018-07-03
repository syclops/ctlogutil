import setuptools

with open('README.md', 'r') as file_handle:
    long_description = file_handle.read()

setuptools.setup(
    name='ctlogutil',
    version='0.0',
    author='Steve Matsumoto',
    description='Certificate Transparency log utility',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/syclops/ctlogutil',
    packages=setuptools.find_packages(),
    classifiers=(
        'Programming Language :: Python :: 3',  # Only compatible with python3
    ),
)