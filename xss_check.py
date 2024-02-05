import requests
import sys
import htmlmin
import argparse
import re
import os
import html

def main():
    parser = argparse.ArgumentParser(description="Utility for checking whether the web resource returned by an HTTP GET request is vulnerable to a reflected server XSS injection through the request's URL parameters. Note that the accuracy of this utility heavily depends on the expected output (e.g., most webpages will incorrectly report having an XSS vulnerability, regardless of payload, if the expected payload is \"<html>\").")

    parser.add_argument('-u', '--url', dest='url', type=str, required=True, help='URL with a single format placeholder included. Example: https://public-firing-range.appspot.com/tags/tag?q={} .')
    parser.add_argument('-p', '--payload-file-path', dest='payload_file_path', type=str, required=True, help='File of payloads to iteratively subsitute for format string placeholder. See payloads.txt for examples.')
    parser.add_argument('-e', '--expected-output-file-paths', dest='expected_output_file_paths', type=str, required=True, help='Comma-separated string of expected outputs for each payload. See expected1.html, expected2.html, ..., expected6.html for examples.')
    parser.add_argument('-v', '--verbose', dest='verbose', default=False, action='store_true', required=False, help="Enable verbose output.")
    parser.add_argument('-s', '--skip-payload-encoding', dest='skip_payload_encoding', default=False, action='store_true', required=False, help="Skip URL encoding the payloads. Necessary when your HTTP GET request requires multiple parameters.")

    args = parser.parse_args()

    url = args.url

    expected_output_file_paths = args.expected_output_file_paths.split(',')

    vulnerable_urls = []

    if len(re.findall(r"(\{\})+", url)) != 1:
        sys.stderr.write("INVALID INPUT: Please ensure that URL has exactly one placeholder (\"{}\") .")
        sys.stderr.write(f" Received URL: \"{url}\"\n")
        sys.exit(1)

    if not os.path.isfile(args.payload_file_path):
        sys.stderr.write(f"INVALID INPUT: Received nonexistent file path {args.payload_file_path} . Please ensure file exists.\n")
        sys.exit(1)

    with open(args.payload_file_path, 'r', encoding='utf-8') as payload_file:
        for i, payload in enumerate(payload_file):

            if i >= len(expected_output_file_paths):
                sys.stderr.write(f"INVALID INPUT: Not enough expected payload file paths for provided payloads.\n")
                sys.exit(1)

            if args.verbose:
                print(payload)

            formatted_url = url.format(payload if args.skip_payload_encoding else requests.utils.quote(payload))
            response = requests.get(formatted_url)

            response_html = response.text

            unescaped_min_response = htmlmin.minify(html.unescape(response_html)).strip()

            min_response = htmlmin.minify(response_html).strip()

            if args.verbose:
                print(response_html)
                print(unescaped_min_response)
                print(min_response)

            with open(expected_output_file_paths[i], 'r', encoding='utf-8') as expected_html_file:
                expected_html = htmlmin.minify(expected_html_file.read()).strip()

            if args.verbose:
                print(expected_html)

            # If expected, minified HTML is found in the minified HTML response
            # or the unescaped, minified HTML response, then we have not found an XSS vulnerability.
            # Otherwise, we have not found an XSS vulnerability.
            if expected_html in unescaped_min_response or expected_html in min_response:
                if args.verbose:
                    print(f"XSS FOUND: Payload \"{payload}\" passed for URL \"{url}\" . Formatted URL was \"{formatted_url}\"")
                vulnerable_urls.append(formatted_url)
            else:
                if args.verbose:
                    print(f"XSS NOT FOUND: Payload \"{payload}\" failed for URL \"{url}\" . Formatted URL was \"{formatted_url}\"")

    if vulnerable_urls:
        print(f"Found {len(vulnerable_urls)} payload(s) to cause reflective server XSS in URL {url}. Corresponding URL(s): ")

        for i, vulnerable_url in enumerate(vulnerable_urls, start=1):
            print(f"{i}) \"{vulnerable_url}\"")
    else:
        print(f"Found 0 payloads to cause reflective server XSS in URL {url}.")

if __name__ == "__main__":
    main()