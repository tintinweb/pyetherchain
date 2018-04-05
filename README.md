# pyetherchain
A python interface to the ethereum blockchain explorer at www.etherchain.org ❤⛓🐍

# Example

```python
# testing, one, two, ...

# accessing an account on etherchain.org (contract, address, ...)
ac = EtherChainAccount("0x6090A6e47849629b7245Dfa1Ca21D94cd15878Ef")
print ac.get()
print ac.history()
print ac.swarm_hash
print ac.transactions()

#accessing raw chart data at etherchain.org
es = EtherChainCharts()
print es.market_cap()

# accessing browsing functionality at etherchain.org
ab = EtherChainBrowser()
print ab.hardforks()
print ab.transactions_pending()

# directly accessing api on etherchain.org
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
```