#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# github.com/tintinweb
#
"""

Python Interface to EtherChain.org

Interfaces
* EtherChainAccount - interface to account/contract addresses
* EtherChainTransaction - interface to transactions
* EtherChain - interface to general discovery/exploration/browsing api on etherchain
* EtherChainCharts - interface to statistics and charting features

Backend
* UserAgent - error correcting user agent for api interface
* EtherChainApi - main api interface

Experimental
* Contract
* AbiFunction
* EtherChainApi - backend api class


"""
import code
import sys
import requests
import re
import time
import xml.etree.ElementTree as ET
import datetime
import json
try:
     # Python 2.6-2.7
    from HTMLParser import HTMLParser
except ImportError:
    # Python 3
    from html.parser import HTMLParser
from eth_abi import (
    decode_abi
)

import logging

logger = logging.getLogger(__name__)


class UserAgent(object):
    """
    User-Agent handling retries and errors ...
    """

    UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36"

    def __init__(self, baseurl, retry=0, retrydelay=6000):
        self.baseurl, self.retry, self.retrydelay = baseurl, retry, retrydelay
        self.initialize()

    def initialize(self):
        self.session = requests.session()
        self.session.headers.update({"user-agent":self.UA})

    def get(self, path, params={}, headers={}):
        new_headers = self.session.headers.copy()
        new_headers.update(headers)

        for _ in range(self.retry):
            try:
                resp = self.session.get("%s%s%s"%(self.baseurl, "/" if not path.startswith("/") else "", path),
                                         params=params, headers=new_headers)
                if resp.status_code != 200:
                    raise Exception("Unexpected Status Code: %s!=200" % resp.status_code)
                return resp
            except Exception as e:
                logger.exception(e)
            logger.warning("Retrying in %d seconds..." % self.retrydelay)
            time.sleep(self.retrydelay)
        raise e

    def post(self, path, params={}, headers={}):
        new_headers = self.session.headers.copy()
        new_headers.update(headers)
        for _ in range(self.retry):
            try:
                resp = self.session.post("%s%s%s"%(self.baseurl, "/" if not path.startswith("/") else "", path),
                                        params=params, headers=new_headers)
                if resp.status_code != 200:
                    raise Exception("Unexpected Status Code: %s!=200" % resp.status_code)
                return resp
            except Exception as e:
                logger.exception(e)
            logger.warning("Retrying in %d seconds..." % self.retrydelay)
            time.sleep(self.retrydelay)
        raise e


class EtherChainApi(object):
    """
    Base EtherChain Api implementation
    """

    def __init__(self):
        self.session = UserAgent(baseurl="https://www.etherchain.org", retry=5, retrydelay=8)

    def get_transaction(self, tx):
        return self.session.get("/api/tx/%s" % tx).json()

    def get_block(self, block):
        return self.session.get("/api/block/%s" % block).json()

    def get_account(self, address):
        return self.session.get("/api/account/%s" % address).json()

    def get_account_history(self, account):
        # https://www.etherchain.org/account/6090a6e47849629b7245dfa1ca21d94cd15878ef/history
        return self.session.get("/account/%s/history" % account).json()

    def _extract_text_from_html(self, s):
        return re.sub('<[^<]+?>', '', s).strip()
        #return ''.join(re.findall(r">(.+?)</", s)) if ">" in s and "</" in s else s

    def _extract_hexstr_from_html_attrib(self, s):
        return ''.join(re.findall(r".+/([^']+)'", s)) if ">" in s and "</" in s else s

    def _get_pageable_data(self, path, start=0, length=10):
        params = {
            "start": start,
            "length": length,
        }
        resp = self.session.get(path, params=params).json()
        # cleanup HTML from response
        for item in resp['data']:
            keys = item.keys()
            for san_k in set(keys).intersection(set(("account", "blocknumber", "type", "direction"))):
                item[san_k] = self._extract_text_from_html(item[san_k])
            for san_k in set(keys).intersection(("parenthash", "from", "to", "address")):
                item[san_k] = self._extract_hexstr_from_html_attrib(item[san_k])
        return resp

    def get_account_transactions(self, account, start=0, length=10):
        # https://www.etherchain.org/account/44919b8026f38d70437a8eb3be47b06ab1c3e4bf/txs?draw=2&start=0&length=9999999&_=1522784788314
        params = {
            'start': start,
            'length': length,
        }
        return self._get_pageable_data("/account/%s/txs" % account, start=start, length=length)

    def get_transactions_pending(self, start=0, length=10):
        #/txs/pending/data?draw=2&columns[0][data]=parenthash&columns[0][name]=&columns[0][searchable]=true&columns[0][orderable]=false&columns[0][search][value]=&columns[0][search][regex]=false&columns[1][data]=time&columns[1][name]=&columns[1][searchable]=true&columns[1][orderable]=false&columns[1][search][value]=&columns[1][search][regex]=false&columns[2][data]=from&columns[2][name]=&columns[2][searchable]=true&columns[2][orderable]=false&columns[2][search][value]=&columns[2][search][regex]=false&columns[3][data]=to&columns[3][name]=&columns[3][searchable]=true&columns[3][orderable]=false&columns[3][search][value]=&columns[3][search][regex]=false&columns[4][data]=value&columns[4][name]=&columns[4][searchable]=true&columns[4][orderable]=false&columns[4][search][value]=&columns[4][search][regex]=false&columns[5][data]=gas&columns[5][name]=&columns[5][searchable]=true&columns[5][orderable]=false&columns[5][search][value]=&columns[5][search][regex]=false&columns[6][data]=gasprice&columns[6][name]=&columns[6][searchable]=true&columns[6][orderable]=false&columns[6][search][value]=&columns[6][search][regex]=false&start=10&length=10&search[value]=&search[regex]=false&_=1522950769145
        return self._get_pageable_data("/txs/pending/data", start=start, length=length)

    def get_transactions(self, start=0, length=10):
        return self._get_pageable_data("/txs/data", start=start, length=length)

    def get_blocks(self, start=0, length=10):
        return self._get_pageable_data("/blocks/data", start=start, length=length)

    def get_accounts(self, start=0, length=10, _type=None):
        if not _type:
            return self._get_pageable_data("/accounts/data", start=start, length=length)
        ret = {"data":[]}
        while True:
            resp = self._get_pageable_data("/accounts/data", start=start, length=length)
            for acc in resp["data"]:
                if acc["type"].lower() == _type:
                    ret["data"].append(EtherChainAccount(acc["address"]))
                    if len(ret["data"]) >= length:
                        ret["processed"] = start+1
                        return ret
                start += 1
            # BUG - we somehow need to also return the amount of skipped entries


    def _parse_tbodies(self, data):
        tbodies = []
        for tbody in re.findall(r"<tbody.*?>(.+?)</tbody>", data):
            rows = []
            for tr in re.findall(r"<tr.*?>(.+?)</tr>", tbody):
                rows.append(re.findall(r"<td.*?>(.+?)</td>", tr))
            tbodies.append(rows)
        return tbodies

    def get_hardforks(self):
        rows = self._parse_tbodies(self.session.get("/hardForks").text)[0]  # only use first tbody
        result = []
        for col in rows:
            result.append({'name': self._extract_text_from_html( col[0]),
                      'on_roadmap': True if "yes" in col[1].lower() else False,
                      'date': self._extract_text_from_html(col[2]),
                      'block': int(self._extract_text_from_html(col[3]))})
        return result

    def get_correlations(self, x=None, y=None, startDate=None, endDate=None):
        if startDate is None:
            # default 1 year
            startDate = datetime.datetime.date(datetime.datetime.now()-datetime.timedelta(days=365)).isoformat()
        if endDate is None:
            endDate = datetime.datetime.date(datetime.datetime.now()).isoformat()
        params = {
            'x': x if x is not None else 'AVG_BLOCK_UTIL',
            'y': y if y is not None else 'AVG_BLOCK_UTIL',
            'startDate': startDate,
            'endDate': endDate,
        }
        return self.session.post("/correlations/data", params=params).json()

    # Economy
    def get_stats_total_ether_supply(self):
        return self.session.get("/charts/totalEtherSupply/data").json()

    def get_stats_market_cap(self):
        return self.session.get("/charts/marketCap/data").json()

    def get_stats_price_usd(self):
        return self.session.get("/charts/priceUSD/data").json()

    def get_stats_price_btc(self):
        return self.session.get("/charts/priceBTC/data").json()

    def get_stats_transactions_per_day(self):
        return self.session.get("/charts/transactionsPerDay/data").json()

    def get_stats_block_gas_usage(self):
        return self.session.get("/charts/blockGasUsage/data").json()

    def get_stats_total_gas_usage(self):
        return self.session.get("/charts/totalGasUsage/data").json()

    def get_stats_average_block_utilization(self):
        return self.session.get("/charts/averageBlockUtilization/data").json()

    # Mining
    def get_stats_hashrate(self):
        return self.session.get("/charts/hashrate/data").json()

    def get_stats_mining_reward(self):
        return self.session.get("/charts/miningReward/data").json()

    def get_stats_block_mining_reward(self):
        return self.session.get("/charts/blockMiningReward/data").json()

    def get_stats_uncle_mining_reward(self):
        return self.session.get("/charts/uncleMiningReward/data").json()

    def get_stats_fee_mining_reward(self):
        return self.session.get("/charts/feeMiningReward/data").json()

    def get_stats_distinct_miners(self):
        return self.session.get("/charts/distinctMiners/data").json()

    def get_stats_mining_revenue(self):
        return self.session.get("/charts/miningRevenue/data").json()

    def get_stats_top_miner_30d(self):
        return self.session.get("/charts/miner/data").json()

    def get_stats_top_miner_24h(self):
        return self.session.get("/charts/topMiners/data").json()

    # Network statistics
    def get_stats_blocks_per_day(self):
        return self.session.get("/charts/blocksPerDay/data").json()

    def get_stats_uncles_per_day(self):
        return self.session.get("/charts/unclesPerDay/data").json()

    def get_stats_block_time(self):
        return self.session.get("/charts/blockTime/data").json()

    def get_stats_difficulty(self):
        return self.session.get("/charts/difficulty/data").json()

    def get_stats_block_size(self):
        return self.session.get("/charts/blockSize/data").json()

    def get_stats_block_gas_limit(self):
        return self.session.get("/charts/blockGasLimit/data").json()

    def get_stats_new_accounts(self):
        return self.session.get("/charts/newAccounts/data").json()

    def get_stats_total_accounts(self):
        return self.session.get("/charts/totalAccounts/data").json()

    # Code

    def _extract_account_info_from_code_tag(self, tagid, s):
        return HTMLParser().unescape(''.join(
            re.findall(r'<code id=\"%s\">(.+?)</code>' % tagid, s, re.DOTALL | re.MULTILINE)))

    def get_account_abi(self, account):
        # <code id="abi">[
        return json.loads(self._extract_account_info_from_code_tag("abi", self.session.get("/account/%s" % account).text))

    def get_account_swarm_hash(self, account):
        return self._extract_account_info_from_code_tag("swarmHash", self.session.get("/account/%s" % account).text)

    def get_account_source(self, account):
        return self._extract_account_info_from_code_tag("source", self.session.get("/account/%s" % account).text)

    def get_account_bytecode(self, account):
        return self._extract_account_info_from_code_tag("contractCode", self.session.get("/account/%s" % account).text)

    def get_account_constructor_args(self, account):
        return self._extract_account_info_from_code_tag("constructorArgs", self.session.get("/account/%s" % account).text)

    # ----------------- OLD STUFF --------------
    def iter_contract(self, ):
        """
        @deprecated

        :return:
        """
        nr = 0
        while True:
            logger.debug("%s/contracts/%d" % (self.BASEURL, nr))

            resp = self.session.get("%s/contracts/%d" % (self.BASEURL, nr))
            #rex is faster than parsing xhtml and fighting with encodings
            root =re.findall("(<table.*<\/table>)",resp.text,re.MULTILINE|re.DOTALL)


            root = ET.fromstring(''.join(root))
            trs = root.findall('tr')
            if not len(trs):
                raise StopIteration()
            for tr in root.findall('tr'):
                tds = tr.findall("td")

                c = Contract(address=tr.attrib["id"].strip(),
                             name=tds[0].findall("a")[0].text.strip(),
                             balance=tds[1].text.strip().split(" ",1)[0],
                             url="%s/account/%s"%(self.BASEURL, tr.attrib["id"].strip()))
                yield c

            nr += 50


class DictLikeInterface(object):

    def __getitem__(self, i):
        return self.data[i]

    def __len__(self):
        return len(self.data)

    def __str__(self):
        return str(self.data)

    def __repr__(self):
        return self.__str__()

    def get(self, k, default=None):
        try:
            return self[k]
        except KeyError:
            return default


class EtherChainTransaction(DictLikeInterface):
    """
    Interface class of an EtherChain Transactions
    """

    def __init__(self, tx, api=None):
        self.tx = tx

        self.api = api or EtherChainApi()

        self.data = self._get()

    def _get(self):
        return self.api.get_transaction(self.tx)


class EtherChainAccount(DictLikeInterface):
    """
    Interface class of an EtherChain account/contract
    """

    TX_TYPE_ALL = 1
    TX_TYPE_INCOMING = 2
    TX_TYPE_OUTGOING = 3
    TX_TYPE_CREATE = 4
    TX_TYPE_CREATION = 5

    def __init__(self, address, api=None):
        self.address = address
        self.abi, self.swarm_hash, self.source, self.code, self.constructor_args = None, None, None, None, None

        self.api = api or EtherChainApi()
        self.data = self._get()
        self._get_extra_info()

    def _get(self):
        return self.api.get_account(self.address)

    def history(self):
        return self.api.get_account_history(self.address)

    def transactions(self, start=0, length=10, direction=None):
        txs = self.api.get_account_transactions(account=self.address, start=start, length=length)
        if not direction:
            return txs

        if direction.lower()=="in":
            txs["data"] = [tx for tx in txs['data'] if "in" in tx["direction"].lower()]
        elif direction.lower()=="out":
            txs["data"] = [tx for tx in txs['data'] if "out" in tx["direction"].lower()]

        return txs

    def _get_extra_info(self):
        s = self.api.session.get("/account/%s" % self.address).text

        try:
            self.abi = ContractAbiEthAbi(json.loads(self.api._extract_account_info_from_code_tag("abi", s)))
        except ValueError:
            logger.debug("could not retrieve contract abi; maybe its just not a contract")
        try:
            self.swarm_hash = self.api._extract_account_info_from_code_tag("swarmHash", s)
        except ValueError:
            logger.debug("could not retrieve swarm hash")
        try:
            self.source = self.api._extract_account_info_from_code_tag("source", s)
        except ValueError:
            logger.debug("could not retrieve contract source code")
        try:
            self.code = self.api._extract_account_info_from_code_tag("contractCode", s)
        except ValueError:
            logger.debug("could not retrieve contract bytecode")
        try:
            self.constructor_args = self.api._extract_account_info_from_code_tag("constructorArgs", s)
        except ValueError:
            logger.debug("could not retrieve contract constructor args")

    def set_abi(self, json_abi):
        self.abi = ContractAbi(json_abi)

    def describe_constructor(self):
        return self.abi.describe_constructor(ContractAbiEthAbi.str_to_bytes(self.constructor_args))

    def describe_transactions(self, length=10000):
        reslt = []
        for tx in self.transactions(direction="in", length=length)["data"]:
            tx_obj = EtherChainTransaction(tx["parenthash"], api=self.api)[0]
            reslt.append((tx_obj["hash"], self.abi.describe_input(ContractAbiEthAbi.str_to_bytes(tx_obj["input"]))))
        return reslt

    def describe_contract(self, nr_of_transactions_to_include=0):
        header = """//***********************************************************
//
// created with pyetherchain.EtherChainAccount(address).describe_contract()
// see: https://github.com/tintinweb/pyetherchain
//
// Date:     %s
//
// Name:     %s
// Address:  %s
// Swarm:    %s
//
//
// Constructor Args: %s
//
//
// Transactions %s: %s
//
//***************************
""" % (time.ctime(),
       self["name"],
       self["address"],
       self.swarm_hash,
       self.describe_constructor(),
       "(last %d)" % nr_of_transactions_to_include if nr_of_transactions_to_include else "",
       "\n//     " + "\n//     ".join(("[IN] %s : %s" % (txhash, txdata) for txhash, txdata in
                                               self.describe_transactions(
                                                   nr_of_transactions_to_include))) if nr_of_transactions_to_include else "<disabled>")

        return "%s%s" % (header, self.source)


class EtherChain(object):
    """
    Interface to EtherChain Browsing featuers
    """

    def __init__(self, api=None):
        self.api = api or EtherChainApi()

        self.charts = EtherChainCharts(api=self.api)

    def transactions_pending(self, start=0, length=10):
        return self.api.get_transactions_pending(start=start, length=length)

    def transactions(self, start=0, length=10):
        return self.api.get_transactions(start=start, length=length)

    def blocks(self, start=0, length=10):
        return self.api.get_blocks(start=start, length=length)

    def accounts(self, start=0, length=10):
        return self.api.get_accounts(start=start, length=length)

    def contracts(self, start=0, length=10):
        return self.api.get_accounts(start=start, length=length, _type="contract")

    def hardforks(self):
        return self.api.get_hardforks()

    def account(self, address):
        return EtherChainAccount(address, api=self.api)

    def transaction(self, tx):
        return EtherChainTransaction(tx, api=self.api)


class ContractAbiEthAbi(object):
    """
    Utility Class to encapsulate a contracts ABI
    """
    def __init__(self, jsonabi):
        self.abi = jsonabi
        self.signatures = {}
        self._prepare_abi(jsonabi)

    @staticmethod
    def str_to_bytes(s):
        """
        Convert 0xHexString to bytes
        :param s: 0x hexstring
        :return:  byte sequence
        """
        return bytes.fromhex(s.replace("0x", ""))

    def _prepare_abi(self, jsonabi):
        """
        Prepare the contract json abi for sighash lookups and fast access

        :param jsonabi: contracts abi in json format
        :return:
        """
        for element_description in jsonabi:
            abi_e = AbiMethodEthAbi(element_description)
            if abi_e["type"] == "constructor":
                self.signatures[b"__constructor__"] = abi_e
            elif abi_e["type"] == "fallback":
                abi_e.setdefault("inputs", [])
                self.signatures[b"__fallback__"] = abi_e
            elif abi_e["type"] == "function":
                self.signatures[ContractAbiEthAbi.str_to_bytes(abi_e["signature"])] = abi_e
            elif abi_e["type"] == "event":
                self.signatures[b"__event__"] = abi_e
            else:
                raise Exception("Invalid abi type: %s - %s - %s" % (abi_e.get("type"),
                                                                    element_description, abi_e))

    def describe_constructor(self, s):
        """
        Describe the input bytesequence (constructor arguments) s based on the loaded contract
         abi definition

        :param s: bytes constructor arguments
        :return: AbiMethod instance
        """
        method = self.signatures.get(b"__constructor__")
        if not method:
            # constructor not available
            m = AbiMethodEthAbi({"type": "constructor", "name": "", "inputs": [], "outputs": []})
            return m

        types_def = method["inputs"]
        types = [t["type"] for t in types_def]
        names = [t["name"] for t in types_def]

        if not len(s):
            values = len(types) * ["<nA>"]
        else:
            values = decode_abi(types, s)

        # (type, name, data)
        method.inputs = [{"type": t, "name": n, "data": v} for t, n, v in list(
            zip(types, names, values))]
        return method

    def describe_input(self, s):
        """
        Describe the input bytesequence s based on the loaded contract abi definition

        :param s: bytes input
        :return: AbiMethod instance
        """
        signatures = self.signatures.items()

        for sighash, method in signatures:
            if sighash is None or sighash.startswith(b"__"):
                continue  # skip constructor

            if s.startswith(sighash):
                s = s[len(sighash):]

                types_def = self.signatures.get(sighash)["inputs"]
                types = [t["type"] for t in types_def]
                names = [t["name"] for t in types_def]

                if not len(s):
                    values = len(types) * ["<nA>"]
                else:
                    values = decode_abi(types, s)

                # (type, name, data)
                method.inputs = [{"type": t, "name": n, "data": v} for t, n, v in list(
                    zip(types, names, values))]
                return method
        else:
            method = AbiMethodEthAbi({"type": "fallback",
                                "name": "__fallback__",
                                "inputs": [], "outputs": []})
            types_def = self.signatures.get(b"__fallback__", {"inputs": []})["inputs"]
            types = [t["type"] for t in types_def]
            names = [t["name"] for t in types_def]

            values = decode_abi(types, s)

            # (type, name, data)
            method.inputs = [{"type": t, "name": n, "data": v} for t, n, v in list(
                zip(types, names, values))]
            return method


class AbiMethodEthAbi(dict):
    """
    Abstraction for an abi method that easily serializes to a human readable format.
    The object itself is an extended dictionary for easy access.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.inputs = []

    def __str__(self):
        return self.describe()

    def describe(self):
        """

        :return: string representation of the methods input decoded with the set abi
        """
        outputs = ", ".join(["(%s) %s" % (o["type"], o["name"]) for o in
                             self["outputs"]]) if self.get("outputs") else ""
        inputs = ", ".join(["(%s) %s = %r" % (i["type"], i["name"], i["data"]) for i in
                            self.inputs]) if self.inputs else ""
        return "%s %s %s returns %s" % (self["type"], self.get("name"), "(%s)" % inputs
            if inputs else "()", "(%s)" % outputs if outputs else "()")


class ContractAbi(object):

    def __init__(self, abi):
        self.abi = abi
        self.signatures = {}
        self._prepare_abi(abi)

    def _str_to_hex(self, s):
        return bytes.fromhex(s.replace("0x",""))

    def _prepare_abi(self, abi):
        for element_description in abi:
            abi_e = AbiMethod(element_description)
            if abi_e["type"] == "constructor":
                # TODO - handle constructor
                self.signatures["__constructor__"] = abi_e
            elif abi_e["type"] == "fallback":
                self.signatures["__fallback__"] = abi_e
            elif abi_e["type"] == "function":
                self.signatures[self._str_to_hex(abi_e["signature"])] = abi_e
            else:
                raise abi_e

    def describe_constructor(self, s):
        result = []

        method = self.signatures.get("__constructor__")
        if not method:
            # constructor not available
            m = AbiMethod({"type": "constructor", "name": "", "inputs": [], "outputs": []})
            m.consume(s)
            result.append(m)
            return result

        method.consume(s)
        result.append(method)

        return result

    def describe_input(self, s):
        result = []
        signatures = self.signatures.items()
        s = self._str_to_hex(s)

        while len(s):
            found = False
            for sighash, method in signatures:
                if sighash is None:
                    continue # skip constructor
                if s.startswith(sighash):
                    s = s[len(sighash):]
                    size = method.consume(s)
                    result.append(method)
                    s = s[size:]
                    found=True
                    break
            if not found:
                m = AbiMethod({"type":"<unknown>","name":"","inputs":[],"outputs":[]})
                m.consume(s)
                result.append(m)
                return result
        return result


class AbiMethod(DictLikeInterface):

    SIZES = {"bytes8": lambda s:8,
             "bytes16": lambda s: 16,
             "bytes32": lambda s:32,
             "uint256": lambda s:256 / 8,
             "int256": lambda s:256 / 8,
             "uint": lambda s:256 / 8,
             "uint8": lambda s:8/8,
             "int": lambda s:256 / 8,
             "bytes": lambda s:100,
             "address": lambda s:160/8,
             "bytes32[]": lambda s: 32,
             "string": lambda s: s.find("\0") if s.find("\0")<32 else 32,
             "address[]": lambda s: 160/8}

    def __init__(self, abi):
        self.data = abi
        self.inputs = []

    def __repr__(self):
        return self.describe()

    def describe(self):
        outputs = ", ".join(["(%s) %s"%(o["type"],o["name"]) for o in self["outputs"]]) if self.get("outputs") else ""
        inputs = ", ".join(["(%s) %s %r"%(i["type"],i["name"],i["data"]) for i in self.inputs]) if self.inputs else ""
        return "%s %s %s returns (%s)" % (self["type"], self.get("name"), "(%s)"%inputs if inputs else "<unknown>", "(%s)" %outputs if outputs else "<unknown>")

    def consume(self, s):
        self.inputs = []
        idx = 0
        if not len(s):
            return idx
        for d_input in self["inputs"]:
            if AbiMethod.SIZES.get(d_input["type"])==None:
                print (d_input["type"])
            size = AbiMethod.SIZES.get(d_input["type"])(s[idx:])
            self.inputs.append({"type":d_input["type"],
                                "name":d_input["name"],
                                "data":s[idx:idx+size]})
            idx += size
        else:
            self.inputs.append({"type":"<unknown>",
                                "name":"",
                                "data":s[idx:]})
            idx = len(s)
        return idx


class EtherChainCharts(object):
    """
    Interface to EtherChain Charts
    """

    def __init__(self, api=None):
        self.api = api or EtherChainApi()

    def correlations(self, x=None, y=None, startDate=None, endDate=None):
        return self.api.get_correlations(x=x, y=y, startDate=startDate, endDate=endDate)

    def total_ether_supply(self):
        return self.api.get_stats_total_ether_supply()
    def market_cap(self):
        return self.api.get_stats_market_cap()
    def price_usd(self):
        return self.api.get_stats_price_usd()
    def price_btc(self):
        return self.api.get_stats_price_btc()
    def transactions_per_day(self):
        return self.api.get_stats_transactions_per_day()
    def block_gas_usage(self):
        return self.api.get_stats_block_gas_usage()
    def total_gas_usage(self):
        return self.api.get_stats_total_gas_usage()
    def average_block_utilization(self):
        return self.api.get_stats_average_block_utilization()
    def hashrate(self):
        return self.api.get_stats_hashrate()
    def mining_reward(self):
        return self.api.get_stats_mining_reward()
    def block_mining_reward(self):
        return self.api.get_stats_block_mining_reward()
    def uncle_mining_reward(self):
        return self.api.get_stats_uncle_mining_reward()
    def fee_mining_reward(self):
        return self.api.get_stats_fee_mining_reward()
    def distinct_miners(self):
        return self.api.get_stats_distinct_miners()
    def mining_revenue(self):
        return self.api.get_stats_mining_revenue()
    def top_miner_30d(self):
        return self.api.get_stats_top_miner_30d()
    def top_miner_24h(self):
        return self.api.get_stats_top_miner_24h()
    def blocks_per_day(self):
        return self.api.get_stats_blocks_per_day()
    def uncles_per_day(self):
        return self.api.get_stats_uncles_per_day()
    def block_time(self):
        return self.api.get_block_time()
    def difficulty(self):
        return self.api.get_stats_difficulty()
    def block_size(self):
        return self.api.get_stats_block_size()
    def block_gas_limit(self):
        return self.api.get_stats_block_gas_limit()
    def new_accounts(self):
        return self.api.get_stats_new_accounts()
    def total_accounts(self):
        return self.api.get_stats_total_accounts()


def interact():
    banner = """
==================================================================

      pyetherchain - cli

==================================================================

Welcome to pyetherchain - the python interface to etherchain.org.
Here's a quick help to get you started :)

Available Classes
* EtherChain - interface to general discovery/exploration/browsing api on etherchain
* EtherChainAccount - interface to account/contract addresses
* EtherChainTransaction - interface to transactions
* EtherChainCharts - interface to statistics and charting features
* EtherChainApi - remote communication api


Available instances:
* etherchain - is an instance of EtherChain() - the main entry point
* api - is an instance of the back-end api connector

* logger - is the module logger instance


Examples:

    etherchain
    etherchain.account("ab7c74abc0c4d48d1bdad5dcb26153fc8780f83e")
    etherchain.account("ab7c74abc0c4d48d1bdad5dcb26153fc8780f83e").describe_contract(nr_of_transactions_to_include=10)
    etherchain.account("ab7c74abc0c4d48d1bdad5dcb26153fc8780f83e").transactions()
    etherchain.transaction("d8df011e6112e2855717a46a16975a3b467bbb69f6db0a26ad6e0803f376dae9")

    etherchain.transactions(start=0, length=10)
    etherchain.transactions_pending(start=0, length=10)
    etherchain.blocks(start=0, length=10)

    etherchain.charts   # access the charts api
    etherchain.charts.price_usd()

    exit() or ctr+c (multiple times) to quit.

"""

    # setup Environment
    #  spawn default connection, share api connection


    api = EtherChainApi()
    etherchain = EtherChain(api=api)

    if len(sys.argv)>2 and sys.argv[1] == "-c":
        print (eval(" ".join(sys.argv[2:]), locals()))
    else:
        try:
            import readline
        except ImportError:
            logger.warning("Module readline not available.")
        else:
            import rlcompleter
            readline.parse_and_bind("tab: complete")
            readline.set_completer(rlcompleter.Completer(locals()).complete)

        code.interact(banner=banner, local=locals())


def main():
    logging.basicConfig(format='[%(filename)s - %(funcName)20s() ][%(levelname)8s] %(message)s',
                        level=logging.INFO)
    logger.setLevel(logging.DEBUG)
    interact()


if __name__ == "__main__":
    main()
    exit()
