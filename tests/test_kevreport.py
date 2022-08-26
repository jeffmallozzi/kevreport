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


async def test_no_config_file():
    """Test file not found error when config file name provided does not exist"""
    sys.argv = [sys.argv[0]]
    sys.argv.extend("-c config.cfg".split())
    with pytest.raises(Exception) as e:
        assert await kevreport.main()
    assert str(e).find("FileNotFoundError") > -1
