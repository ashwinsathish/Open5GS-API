import argparse
from . import __version__

def main():
    parser = argparse.ArgumentParser(description='Open5GS API')
    parser.add_argument('--version', action='version', version=f'open5gsapi {__version__}')
    parser.parse_args()

if __name__ == '__main__':
    main()