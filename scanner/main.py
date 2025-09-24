import argparse
from scanner.core import VulnerabilityScanner


def main():
    parser = argparse.ArgumentParser(description="OWASP PR Vulnerability Scanner")
    parser.add_argument("path", help="Path to Python file to scan")
    args = parser.parse_args()

    scanner = VulnerabilityScanner(args.path)
    scanner.run()
    scanner.report()

if __name__ == "__main__":
    main()
