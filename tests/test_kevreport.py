import asyncio
import sys

import pytest

import kevreport


def test_version():
    """Test the version number"""
    assert kevreport.__version__ == "0.1.0"


def test_args():
    """Test the default args"""
    args = kevreport.parse_args()
    assert args.profile is None
    assert args.config == "kevreport.cfg"


def test_args_profile():
    """Test profile name provided as arg"""
    sys.argv = [sys.argv[0]]
    sys.argv.extend("-p profile01".split())
    args = kevreport.parse_args()
    assert args.profile == "profile01"


def test_args_config():
    """Test config file provided as arg"""
    sys.argv = [sys.argv[0]]
    sys.argv.extend("-c config.cfg".split())
    args = kevreport.parse_args()
    assert args.config == "config.cfg"


def test_args_version():
    """Test verion number output when --version is in args"""
    sys.argv = [sys.argv[0]]
    sys.argv.extend("--version".split())
    args = kevreport.parse_args()
    assert args.version is True


def test_intersect_01():
    """Test intersect function"""
    assert kevreport.intersect(
        ["bob", "bob", "jill", "sam", "barb"], ["barb", "bob", "roger"]
    ) == ["barb", "bob"]


def test_chunk():
    """Test chunk function"""
    for chunk in kevreport.chunk([1, 2, 3, 4, 5, 6, 7, 8], 3):
        assert len(chunk) <= 3


def test_format_date():
    """Test the format_date() function"""
    date = kevreport.format_date(1661623579)
    assert date == "2022-08-27"


def test_get_kev():
    """Test the get_kev() function"""
    kev = kevreport.get_kev(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    assert kev[0].get("cveID", None) is not None


def test_sort_by_due_date():
    """Test the sort_by_due_date() function"""
    sorted_kev = kevreport.sort_by_due_date(moc_kev)
    assert "CVE-2018-4939" in sorted_kev.get("2022-05-03")
    assert len(sorted_kev.get("2022-05-03")) == 4


async def test_no_config_file():
    """Test file not found error when config file name provided does not exist"""
    sys.argv = [sys.argv[0]]
    sys.argv.extend("-c config.cfg".split())
    with pytest.raises(Exception) as e:
        assert await kevreport.main()
    assert str(e).find("FileNotFoundError") > -1


moc_kev = [
    {
        "cveID": "CVE-2021-28550",
        "vendorProject": "Adobe",
        "product": "Acrobat and Reader",
        "vulnerabilityName": "Adobe Acrobat and Reader Use-After-Free Vulnerability",
        "dateAdded": "2021-11-03",
        "shortDescription": "Acrobat Reader DC versions versions 2021.001.20150 (and earlier), 2020.001.30020 (and earlier) and 2017.011.30194 (and earlier) are affected by a Use After Free vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2021-11-17",
        "notes": "",
    },
    {
        "cveID": "CVE-2018-4939",
        "vendorProject": "Adobe",
        "product": "ColdFusion",
        "vulnerabilityName": "Adobe ColdFusion Deserialization of Untrusted Data vulnerability",
        "dateAdded": "2021-11-03",
        "shortDescription": "Adobe ColdFusion Update 5 and earlier versions, ColdFusion 11 Update 13 and earlier versions have an exploitable Deserialization of Untrusted Data vulnerability. Successful exploitation could lead to arbitrary code execution.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-05-03",
        "notes": "",
    },
    {
        "cveID": "CVE-2018-15961",
        "vendorProject": "Adobe",
        "product": "ColdFusion",
        "vulnerabilityName": "Adobe ColdFusion Remote Code Execution",
        "dateAdded": "2021-11-03",
        "shortDescription": "Adobe ColdFusion versions July 12 release (2018.0.0.310739), Update 6 and earlier, and Update 14 and earlier have an unrestricted file upload vulnerability. Successful exploitation could lead to arbitrary code execution.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-05-03",
        "notes": "",
    },
    {
        "cveID": "CVE-2018-4878",
        "vendorProject": "Adobe",
        "product": "Flash Player",
        "vulnerabilityName": "Adobe Flash Player Use-After-Free Vulnerability",
        "dateAdded": "2021-11-03",
        "shortDescription": "A use-after-free vulnerability was discovered in Adobe Flash Player before 28.0.0.161. This vulnerability occurs due to a dangling pointer in the Primetime SDK related to media player handling of listener objects. A successful attack can lead to arbitrary code execution. This was exploited in the wild in January and February 2018.",
        "requiredAction": "The impacted product is end-of-life and should be disconnected if still in use.",
        "dueDate": "2022-05-03",
        "notes": "",
    },
    {
        "cveID": "CVE-2020-5735",
        "vendorProject": "Amcrest",
        "product": "Cameras and Network Video Recorder (NVR)",
        "vulnerabilityName": "Amcrest Camera and NVR Buffer Overflow Vulnerability",
        "dateAdded": "2021-11-03",
        "shortDescription": "Amcrest cameras and NVR are vulnerable to a stack-based buffer overflow over port 37777. An authenticated remote attacker can abuse this issue to crash the device and possibly execute arbitrary code.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-05-03",
        "notes": "",
    },
    {
        "cveID": "CVE-2014-4404",
        "vendorProject": "Apple",
        "product": "OS X",
        "vulnerabilityName": "Apple OS X Heap-Based Buffer Overflow Vulnerability",
        "dateAdded": "2022-02-10",
        "shortDescription": "Heap-based buffer overflow in IOHIDFamily in Apple OS X, which affects, iOS before 8 and Apple TV before 7, allows attackers to execute arbitrary code in a privileged context.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-08-10",
        "notes": "",
    },
    {
        "cveID": "CVE-2022-22620",
        "vendorProject": "Apple",
        "product": "Webkit",
        "vulnerabilityName": "Apple Webkit Remote Code Execution Vulnerability",
        "dateAdded": "2022-02-11",
        "shortDescription": "Apple Webkit, which impacts iOS, iPadOS, and macOS, contains a vulnerability which allows for remote code execution.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-02-25",
        "notes": "",
    },
    {
        "cveID": "CVE-2022-24086",
        "vendorProject": "Adobe",
        "product": "Commerce and Magento Open Source",
        "vulnerabilityName": "Adobe Commerce and Magento Open Source Improper Input Validation Vulnerability",
        "dateAdded": "2022-02-15",
        "shortDescription": "Adobe Commerce and Magento Open Source contain an improper input validation vulnerability which can allow for arbitrary code execution.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-03-01",
        "notes": "",
    },
    {
        "cveID": "CVE-2022-0609",
        "vendorProject": "Google",
        "product": "Chrome",
        "vulnerabilityName": "Google Chrome Use-After-Free Vulnerability",
        "dateAdded": "2022-02-15",
        "shortDescription": "The vulnerability exists due to a use-after-free error within the Animation component in Google Chrome.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-03-01",
        "notes": "",
    },
]
