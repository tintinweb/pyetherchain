#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# github.com/tintinweb
#
"""

Python Interface to EtherChain.org

Interfaces
* EtherChainAccount - interface to account/contract addresses
* EtherChainTransaction - interface to transactions
* EtherChainBrowser - interface to general discovery/exploration/browsing api on etherchain
* EtherChainCharts - interface to statistics and charting features

Backend
* UserAgent - error correcting user agent for api interface
* EtherChainApi - main api interface

Experimental
* Contract
* AbiFunction
* EtherChainApi - backend api class


"""
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

        for _ in xrange(self.retry):
            try:
                return self.session.get("%s%s%s"%(self.baseurl, "/" if not path.startswith("/") else "", path),
                                         params=params, headers=new_headers)
            except Exception, e:
                logger.exception(e)
            time.sleep(self.retrydelay)
        raise e

    def post(self, path, params={}, headers={}):
        new_headers = self.session.headers.copy()
        new_headers.update(headers)
        for _ in xrange(self.retry):
            try:
                return self.session.post("%s%s%s"%(self.baseurl, "/" if not path.startswith("/") else "", path),
                                        params=params, headers=new_headers)
            except Exception, e:
                logger.exception(e)
            time.sleep(self.retrydelay)
        raise e


class EtherChainApi(object):
    """
    Base EtherChain Api implementation
    """

    def __init__(self):
        self.session = UserAgent(baseurl="https://www.etherchain.org", retry=2, retrydelay=8000)

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
        return ''.join(re.findall(r">(.+?)</", s))

    def _extract_hexstr_from_html_attrib(self, s):
        return ''.join(re.findall(r".+/([^']+)'", s))

    def _get_pageable_data(self, path, start=0, length=10):
        params = {
            "start": start,
            "length": length,
        }
        resp = self.session.get(path, params=params).json()
        # cleanup HTML from response
        for item in resp['data']:
            keys = item.keys()
            for san_k in set(keys).intersection(set(("blocknumer","type","direction"))):
                item[san_k] = self._extract_text_from_html(item[san_k])
            for san_k in set(keys).intersection(("parenthash", "from","to")):
                item[san_k] = self._extract_hexstr_from_html_attrib(item[san_k])
        return resp

    def get_account_transactions(self, account, start=0, length=10):
        # https://www.etherchain.org/account/44919b8026f38d70437a8eb3be47b06ab1c3e4bf/txs?draw=2&start=0&length=9999999&_=1522784788314
        params = {
            'start': start,
            'length': length,
        }
        return self._get_pageable_data("/account/%s/txs" % account)

    def get_transactions_pending(self, start=0, length=10):
        #/txs/pending/data?draw=2&columns[0][data]=parenthash&columns[0][name]=&columns[0][searchable]=true&columns[0][orderable]=false&columns[0][search][value]=&columns[0][search][regex]=false&columns[1][data]=time&columns[1][name]=&columns[1][searchable]=true&columns[1][orderable]=false&columns[1][search][value]=&columns[1][search][regex]=false&columns[2][data]=from&columns[2][name]=&columns[2][searchable]=true&columns[2][orderable]=false&columns[2][search][value]=&columns[2][search][regex]=false&columns[3][data]=to&columns[3][name]=&columns[3][searchable]=true&columns[3][orderable]=false&columns[3][search][value]=&columns[3][search][regex]=false&columns[4][data]=value&columns[4][name]=&columns[4][searchable]=true&columns[4][orderable]=false&columns[4][search][value]=&columns[4][search][regex]=false&columns[5][data]=gas&columns[5][name]=&columns[5][searchable]=true&columns[5][orderable]=false&columns[5][search][value]=&columns[5][search][regex]=false&columns[6][data]=gasprice&columns[6][name]=&columns[6][searchable]=true&columns[6][orderable]=false&columns[6][search][value]=&columns[6][search][regex]=false&start=10&length=10&search[value]=&search[regex]=false&_=1522950769145
        return self._get_pageable_data("/txs/pending/data", start=start, length=length)

    def get_transactions(self, start=0, length=10):
        return self._get_pageable_data("/txs/data", start=start, length=length)

    def get_blocks(self, start=0, length=10):
        return self._get_pageable_data("/blocks/data", start=start, length=length)

    def get_accounts(self, start=0, length=10):
        return self._get_pageable_data("/accounts/data", start=start, length=length)

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

    def getAccountTransactions(self, address, start=0, length=500, _filter=None):
        """
        @deprecated

        :param address:
        :param start:
        :param length:
        :param _filter:
        :return:
        """
        # https://www.etherchain.org/account/44919b8026f38d70437a8eb3be47b06ab1c3e4bf/txs?draw=2&start=0&length=9999999&_=1522784788314
        resp = self.session.get("%s/account/%s/txs?start=%d&length=%d"%(self.BASEURL, address, start, length))
        for item in resp.json().get("data",[]):
            yield ''.join(re.findall("\'/tx/([^\']+)\'", item["parenthash"]))

    # @deprecated
    def getContractAbiFromHtml(self, address):
        """
        @deprecated

        :param address:
        :return:
        """
        resp = self.session.get("%s/account/%s" % (self.BASEURL, address))
        rslt = []
        for _ in re.findall(r"<tr><td>function</td><td>([^<]+)</td><td>([^<]+)</td><td>([^<]+)</td></tr>", resp.text):
            rslt.append(dict(zip(["name","constant","signature"], _)))

        contract = ContractAbi(address)
        for _ in rslt:
            contract.addAbiFunction(name=_["name"], signature=_["signature"].replace("0x","").decode("hex"), constant=_["constant"])

        return contract


class EtherChainAccount(object):
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
        self._get_extra_info()

    def get(self):
        return self.api.get_account(self.address)

    def history(self):
        return self.api.get_account_history(self.address)

    def transactions(self, start=0, length=10, txtype=TX_TYPE_ALL):
        txs = self.api.get_account_transactions(account=self.address, start=start, length=length)
        if txtype == EtherChainAccount.TX_TYPE_OUTGOING:
            txs = [tx for tx in txs if tx['sender'].lower() == self.address.lower()]
        elif txtype == EtherChainAccount.TX_TYPE_INCOMING:
            txs = [tx for tx in txs if tx['recipient'].lower() == self.address.lower()]
        elif txtype == EtherChainAccount.TX_TYPE_CREATE:
            # outgoing
            txs = [tx for tx in txs if tx['sender'].lower() == self.address.lower() and tx['newContract'] != 0]
        elif txtype == EtherChainAccount.TX_TYPE_CREATION:
            # incoming
            txs = [tx for tx in txs if tx['recipient'].lower() == self.address.lower() and tx['newContract'] != 0]
        return txs

    def _get_extra_info(self):
        s = self.api.session.get("/account/%s" % self.address).text

        self.abi = json.loads(self.api._extract_account_info_from_code_tag("abi", s))
        self.swarm_hash = self.api._extract_account_info_from_code_tag("swarmHash", s)
        self.source = self.api._extract_account_info_from_code_tag("source", s)
        self.code = self.api._extract_account_info_from_code_tag("contractCode", s)
        self.constructor_args = self.api._extract_account_info_from_code_tag("constructorArgs", s)


class EtherChainTransaction(object):
    """
    Interface class of an EtherChain Transactions
    """

    def __init__(self, tx, api=None):
        self.tx = tx

        self.api = api or EtherChainApi()

    def get(self):
        return self.api.get_transaction(self.tx)


class EtherChainBrowser(object):
    """
    Interface to EtherChain Browsing featuers
    """

    def __init__(self, api=None):
        self.api = api or EtherChainApi()

    def transactions_pending(self, start=0, length=10):
        return self.api.get_transactions_pending(start=start, length=length)

    def transactions(self, start=0, length=10):
        return self.api.get_transactions(start=start, length=length)

    def blocks(self, start=0, length=10):
        return self.api.get_blocks(start=start, length=length)

    def accounts(self, start=0, length=10):
        return self.api.get_accounts(start=start, length=length)

    def hardforks(self):
        return self.api.get_hardforks()


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


if __name__ == "__main__":
    # testing, one, two, ...
    e = EtherChainApi()
    #print e.get_transaction("c98061e6e1c9a293f57d59d53f4e171bb62afe3e5b6264e9a770406a81fb1f07")
    #print e.get_transactions_pending()
    #print e.get_transactions()
    #print e.get_blocks()
    #print e.get_accounts()
    #print e.get_hardforks()
    #print e.get_correlations()
    #print e.get_stats_price_btc()
    print e.get_account_transactions("0x1104e154efa21ff3ca5da097f8906cd56b1e7d86")
    try:
        print e.get_account_abi("0x1104e154efa21ff3ca5da097f8906cd56b1e7d86")
        print e.get_account_source(("0x1104e154efa21ff3ca5da097f8906cd56b1e7d86"))
    except Exception, e:
        pass

    ac = EtherChainAccount("0x6090A6e47849629b7245Dfa1Ca21D94cd15878Ef")
    print ac.get()
    print ac.history()
    print ac.swarm_hash
    print ac.transactions()

    es = EtherChainCharts()
    print es.market_cap()

    ab = EtherChainBrowser()
    print ab.hardforks()
    print ab.transactions_pending()


'''
exit()

class Contract(object):

    def __init__(self, address, name=None, balance=None, url=None,):
        self.address, self.name, self.balance, self.url = address, name, balance, url

    def __str__(self):
        return "address=%s name=%s balance=%s url=%s"%(self.address, self.name, self.balance, self.url)


A = """
<table>
<tr id="0xdcb13fa157eebf22ddc8c9aa1d6e394810de6fa3">
<td>
<a href="/account/0xdcb13fa157eebf22ddc8c9aa1d6e394810de6fa3">
PiggyBank
</a>
</td>
<td>2.5454983753768463 Ether ($761.59)</td>
<td>Yes</td>
</tr>
</table>

"""




class ContractAbi(object):

    def __init__(self, address):
        self.methods = []
        self.signatures = {}
        self.address = address

    def addAbiFunction(self, name, signature, constant=None):
        abimethod = AbiFunction(name=name, signature=signature, constant=constant)
        self.signatures[signature] = abimethod
        self.methods.append(abimethod)

    def consume(self, s):
        result = []
        signatures = self.signatures.items()
        while len(s):

            for sighash, method in signatures:
                if s.startswith(sighash):
                    s = s[len(sighash):]
                    m, size = method.consume(s)
                    result.append((method.function["name"],"==>",method.function["return"], m))
                    s = s[size:]
            else:
                return result
        return result

class AbiFunction(object):

    SIZES = {"bytes8": 8,
             "bytes16":16,
             "bytes32":32,
             "uint256":256/8,
             "bytes":100,
             "address":40,
             "bytes32[]":32}

    def __init__(self, name, constant=None, signature=None):
        self.constant, self.signature = constant, signature
        self.nametxt = name
        self.function = AbiFunction.parse_function(name)

    def consume(self, s):
        result = []
        idx = 0
        for atype, aname in self.function["args"]:
            size = AbiFunction.SIZES.get(atype)
            result.append((atype, aname, s[idx:idx+size]))
            idx+=size
        return result, idx

    @staticmethod
    def parse_function(ftxt):
        name, rest = ftxt.split("(",1)
        rvalue = ""
        if " => " in rest:
            rest, rvalue = rest.split(" => ",1)
        args = []
        for a in rest.replace(")","").strip().split(","):
            if " " in a.strip():
                aname, atype = a.strip().split(" ")
                args.append([atype, aname])
        rvalue = [r.strip() for r in rvalue.replace("(","").replace(")","").strip().split(",")]


        return {"name":name.strip(), "args":args, "return":rvalue}


if __name__=="__main__":
    ec = EtherChainApi()
    contract = ec.getContractAbiFromHtml("6090a6e47849629b7245dfa1ca21d94cd15878ef")
    for tx in  ec.getAccountTransactions("6090a6e47849629b7245dfa1ca21d94cd15878ef"):
        for trans in ec.get_transaction(tx):
            if trans.get("to") == "6090a6e47849629b7245dfa1ca21d94cd15878ef":
                print contract.consume(trans["input"].decode("hex"))
    #for c in ec.iter_contracts():
    #    print c
'''