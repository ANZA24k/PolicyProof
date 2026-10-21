import copy
import hashlib
import json
import re
import pytest
from test_policyproof import env, prepare, state, result, BUNDLE, ANSWER, DOC, SOURCE, URL, POLICY, C, H

@pytest.mark.parametrize('location',['bundle','source'])
def test_invalid_utf8_permanent_repeated_evaluation_and_recovery(env,location):
    vm,c=env;bad=b'\xff\xfeinvalid utf8';b=copy.deepcopy(BUNDLE)
    if location=='bundle':
        c.submit_assessment('incident','case-good','Aurora INC-42','2026-10-01',URL,hashlib.sha256(bad).hexdigest())
        vm.mock_web(re.escape(URL),{'status':200,'body':bad})
    else:
        b['sources'][0]['sha256']=hashlib.sha256(bad).hexdigest()
        prepare(vm,c,bundle=b,doc=bad)
    c.evaluate('case-good');assert result(c)=={'verdict':'INCONCLUSIVE','error':'INVALID_UTF8','findings':[]};assert vm.run_validator()
    original=copy.deepcopy(state(c)['history'])
    with vm.expect_revert('Revision already reviewed'):c.evaluate('case-good')
    assert state(c)['history']==original
    vm.sender='0x'+'b'*40
    with vm.expect_revert('Only assessment owner'):c.revise_evidence('case-good',URL,H(C(BUNDLE)))
    vm.sender='0x'+'a'*40;c.revise_evidence('case-good',URL,H(C(BUNDLE)))
    vm.clear_mocks();vm.mock_web(re.escape(URL),{'status':200,'body':C(BUNDLE)});vm.mock_web(re.escape(SOURCE),{'status':200,'body':DOC});vm.mock_llm('operational policy evidence assessor',C(ANSWER))
    c.evaluate('case-good');assert result(c)['verdict']=='PASS';assert state(c)['revision']==2
    assert state(c)['history'][0]==original[0];assert vm.run_validator()


def verify_snapshot(history):
    r=history['result'];p=r['packet'];assert H(C(p))==r['packet_sha256'];assert H(p['bundle']['text'])==p['bundle']['sha256']==history['sha256']
    refs=json.loads(p['bundle']['text'])['sources']
    for d,ref in zip(p['sources'],refs):assert H(d['text'])==d['sha256']==ref['sha256'] and d['url']==ref['url']
    for f in p['findings']:
        if f['state']!='UNKNOWN':
            doc=p['sources'][f['source']]['text'];cursor=0
            for excerpt in f['quote'].split('\n'):
                pos=doc.find(excerpt,cursor);assert pos>=0;cursor=pos+len(excerpt)
    assert r['findings']==p['findings']


def test_durable_audit_reconstruction_after_source_mutation_and_revisions(env):
    vm,c=env;prepare(vm,c);c.evaluate('case-good');first=copy.deepcopy(state(c)['history'][0]);verify_snapshot(first)
    vm.clear_mocks();vm.mock_web(re.escape(SOURCE),{'status':200,'body':'changed or unavailable source'})
    verify_snapshot(first) # Reconstruction never consults the changed URL.
    b=copy.deepcopy(BUNDLE);newdoc=DOC+'\nCorrected supplemental incident record.';b['sources'][0]['sha256']=H(newdoc)
    newurl=URL.replace('pass.json','revision2.json');c.revise_evidence('case-good',newurl,H(C(b)))
    vm.clear_mocks();vm.mock_web(re.escape(newurl),{'status':200,'body':C(b)});vm.mock_web(re.escape(SOURCE),{'status':200,'body':newdoc});vm.mock_llm('operational policy evidence assessor',C(ANSWER))
    c.evaluate('case-good');history=state(c)['history'];assert history[0]==first
    assert history[1]['result']['packet']['revision']==2
    for h in history:verify_snapshot(h)
    assert history[0]['result']['packet']['sources'][0]['text']!=history[1]['result']['packet']['sources'][0]['text']


def test_validators_accept_different_verbatim_quotes_but_same_decision(env):
    vm,c=env;prepare(vm,c);c.evaluate('case-good');a=copy.deepcopy(ANSWER)
    a['findings'][0]['quote']='Acknowledged at 09:12 UTC. Customer notice published at 09:40 UTC.'
    vm.clear_mocks();vm.mock_web(re.escape(URL),{'status':200,'body':C(BUNDLE)});vm.mock_web(re.escape(SOURCE),{'status':200,'body':DOC});vm.mock_llm('operational policy evidence assessor',C(a))
    assert vm.run_validator();assert result(c)['findings'][0]['quote']==ANSWER['findings'][0]['quote']

@pytest.mark.parametrize('mutation',['quote','source','snapshot','bundle','policy','packet_hash','finding','extra'])
def test_forged_historical_packet_is_rejected(env,mutation):
    vm,c=env;prepare(vm,c);c.evaluate('case-good');r=copy.deepcopy(result(c))
    if mutation=='quote':r['packet']['findings'][0]['quote']='Invented approval quotation'
    elif mutation=='source':r['packet']['findings'][0]['source']=99
    elif mutation=='snapshot':r['packet']['sources'][0]['text']='Modified source content'
    elif mutation=='bundle':r['packet']['bundle']['text']='{}'
    elif mutation=='policy':r['packet']['policy']['scope']='Replaced policy'
    elif mutation=='finding':r['packet']['findings'][0]['state']='VIOLATED';r['findings']=copy.deepcopy(r['packet']['findings']);r['verdict']='FAIL'
    elif mutation=='extra':r['packet']['extra']='trust me'
    if mutation!='packet_hash':r['packet_sha256']=H(C(r['packet']))
    else:r['packet_sha256']='0'*64
    assert not vm.run_validator(leader_result=r)


def test_source_snapshot_budget_is_permanent_not_a_deadlock(env):
    vm,c=env;b=copy.deepcopy(BUNDLE);long='x'*15000
    b['sources']=[{'url':SOURCE,'sha256':H(long)},{'url':SOURCE.replace('report.txt','report2.txt'),'sha256':H(long)}]
    prepare(vm,c,bundle=b,doc=long);vm.mock_web(re.escape(b['sources'][1]['url']),{'status':200,'body':long});c.evaluate('case-good')
    assert result(c)['error']=='SOURCE_BUDGET_EXCEEDED'
    c.revise_evidence('case-good',URL,H(C(BUNDLE)));assert state(c)['revision']==2
