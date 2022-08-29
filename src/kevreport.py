#!/usr/bin/env python3
import argparse
import asyncio
import configparser
import logging
from asyncio.log import logger
from csv import DictWriter
from datetime import datetime
from pathlib import Path

import requests
from tenable.sc import TenableSC

__version__ = "0.1.0"
sem = asyncio.Semaphore(3)


def parse_args() -> argparse.Namespace:
    """Define command line arguments and returns the parsed
    argument parser"""
    parser = argparse.ArgumentParser()

    parser.add_argument("-p", "--profile")
    parser.add_argument("-c", "--config", default="kevreport.cfg")
    parser.add_argument("--version", action="store_true", default=False)

    return parser.parse_args()


def intersect(list_a: list[str], list_b: list[str]) -> list[str]:
    """Returns a list which is the intersection of two lists,
    duplicates are removed"""
    return sorted(list(set(list_a) & set(list_b)))


def chunk(lst: list, chunk_size: int) -> list:
    """Generator for yeilding chuncks of a list"""
    for i in range(0, len(lst), chunk_size):
        yield lst[i : i + chunk_size]


def format_date(timestamp: int) -> str:
    """Returns a formated string from a timestamp int"""
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d")


def get_kev(url: str) -> dict:
    """Retrieves the KEV from CISA and returns it in json format"""
    resp = requests.get(url)
    return resp.json()["vulnerabilities"]


def sort_by_due_date(kev: list[dict]) -> dict:
    """Takes the KEV list and creates a dict with each unique
    due date as keys and the list of CVEs as values"""
    resp = {}
    for vuln in kev:
        resp.setdefault(vuln["dueDate"], []).append(vuln["cveID"])
    return resp


async def get_vulns(
    cve_list: list[str],
    due_date: str,
    config: configparser.ConfigParser,
    profile: str,
) -> list[dict]:
    """Queries Tenable.sc for all vulnerabilites associated with the
    provided list of CVE. Date fields are properly formated. Returns a list"""
    logger.info(f"Starting Due Date: {due_date}")
    logger.debug(f"CVE List: {cve_list}")

    vulns = []

    async with sem:
        with TenableSC(
            config[profile]["host"],
            config[profile]["access_key"],
            config[profile]["secret_key"],
        ) as sc:
            for cves in chunk(cve_list, int(config[profile]["chunk_size"])):
                filters = [
                    ("cveID", "=", ",".join(cves)),
                    (
                        "repository",
                        "=",
                        [int(x) for x in config[profile]["repos"].split()],
                    ),
                    ("acceptRiskStatus", "=", config[profile]["accept_risk"]),
                ]
                kwargs = {"tool": "vulndetails"}

                result = sc.analysis.vulns(*filters, **kwargs)

                for vuln in result:
                    vuln["CISA_due_date"] = due_date
                    vuln["cve"] = ",".join(
                        intersect(cve_list, vuln["cve"].split(","))
                    )
                    vuln["firstSeen"] = format_date(int(vuln["firstSeen"]))
                    vuln["lastSeen"] = format_date(int(vuln["lastSeen"]))
                    vulns.append(vuln)

    logger.info(
        f"Finishing Due Date: {due_date} with {len(vulns)} vulnerabilities"
    )
    return vulns


def sort_vulns_by_repo(vulns: list[dict]) -> dict:
    """Takes a list of vulnerabilities and creates a dict with repository
    names as the keys and the list of vulnerabilities as the values"""
    resp = {}
    for vuln in vulns:
        resp.setdefault(vuln["repository"]["name"], []).append(vuln)

    return resp


async def write_file(
    repo: str, vuln_list: list[str], field_names: list[str]
) -> str:
    """Writes out the csv file for the list of vulnerabilities. Returns
    the name of the file"""
    filename = (
        f"BOD-22-01-KEV-{repo}-{datetime.now().strftime('%Y-%m-%d')}.csv"
    )
    field_names = ["CISA_due_date"].extend(field_names)
    with open(filename, "w", newline="") as cf:
        writer = DictWriter(cf, fieldnames=field_names, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(vuln_list)

    return filename


async def main():
    """Entry Point"""
    # Get args
    args = parse_args()
    if args.version:
        print(f"Version: {__version__}")
        return

    # Configure logging
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.DEBUG)

    # Get config
    logger.debug(f"Fetching config from file: {args.config}")
    if not Path(args.config).exists():
        raise FileNotFoundError(f"Config file: {args.config} does not exist")

    config = configparser.ConfigParser()
    config.read(Path(args.config))
    profile = args.profile or config["DEFAULT"]["default_profile"]

    for item in config[profile]:
        print(f"{item}: {config[profile][item]}")

    # Get KEV
    kev = get_kev(config[profile]["kev_url"])

    # Parse KEV sort by due date
    cves_by_due_date = sort_by_due_date(kev)

    # Get vulns from SC
    vulns = await asyncio.gather(
        *[
            get_vulns(cve_list, due_date, config, profile)
            for due_date, cve_list in cves_by_due_date.items()
        ]
    )

    # flaten vulns
    flat_vulns = []
    for vuln in vulns:
        flat_vulns.extend(vuln)

    # Sort vulns by repo
    vulns_by_repo = sort_vulns_by_repo(flat_vulns)

    # Output files
    output_fields = config[profile]["fields"].split()
    output_files = await asyncio.gather(
        *[
            write_file(repo, vuln_list, output_fields)
            for repo, vuln_list in vulns_by_repo.items()
        ]
    )
    logger.info(f"The following output files were created: {output_files}")


if __name__ == "__main__":
    asyncio.run(main())
