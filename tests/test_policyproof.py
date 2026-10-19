import copy
import hashlib
import json
import re
from pathlib import Path
import pytest
from gltest.direct import VMContext, deploy_contract

ROOT = Path(__file__).parents[1]
POLICY = {'name':'Incident response', 'scope':'Synthetic Aurora service incident INC-42 during 2026-10-01.', 'criteria':[{'id':'ACK','requirement':'Acknowledge the incident within 30 minutes of detection.'},{'id':'NOTICE','requirement':'Publish a customer notice within 2 hours of detection.'}]}
URL = 'https://raw.githubusercontent.com/ANZA24k/PolicyProof/'+'1'*40+'/evidence/pass.json'
SOURCE = URL.replace('pass.json','report.txt')
DOC = 'INC-42 detected at 09:00 UTC on 2026-10-01. Acknowledged at 09:12 UTC. Customer notice published at 09:40 UTC.'
C = lambda x: json.dumps(x, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
H = lambda x: hashlib.sha256(x.encode()).hexdigest()
BUNDLE = {'schema':'policyproof/v1','synthetic':True,'assessment_id':'case-good','policy_sha256':H(C(POLICY)), 'subject':'Aurora INC-42','period':'2026-10-01','sources':[{'url':SOURCE,'sha256':H(DOC)}]}
ANSWER = {'findings':[{'id':'ACK','state':'SATISFIED','source':0,'quote':'Acknowledged at 09:12 UTC.'},{'id':'NOTICE','state':'SATISFIED','source':0,'quote':'Customer notice published at 09:40 UTC.'}]}

@pytest.fixture
def env():
    vm=VMContext()
    with vm.activate():
        vm.sender='0x'+'a'*40
        c=deploy_contract(ROOT/'contracts/policyproof.py',vm,sdk_version='v0.2.16')
        c.create_policy('incident',C(POLICY))
        yield vm,c

def prepare(vm,c,bundle=None,answer=None,raw=None,status=200,expected=None,doc=DOC):
    raw=raw if raw is not None else C(bundle or BUNDLE)
    c.submit_assessment('incident','case-good','Aurora INC-42','2026-10-01',URL,expected or H(raw))
    vm.mock_web(re.escape(URL),{'status':status,'body':raw})
    vm.mock_web(re.escape(SOURCE),{'status':200,'body':doc})
    vm.mock_llm('operational policy evidence assessor',C(answer or ANSWER))

def state(c): return json.loads(c.get_assessment('case-good'))
def result(c): return state(c)['history'][-1]['result']

def test_pass_and_independent_consensus(env):
    vm,c=env;prepare(vm,c);c.evaluate('case-good')
    assert result(c)['verdict']=='PASS' and vm.run_validator()
    assert json.loads(c.get_policy('incident'))['sha256']==H(C(POLICY))
    assert not vm.run_validator(leader_result={'verdict':'PASS'})
    assert not vm.run_validator(leader_error=ValueError('fake'))

@pytest.mark.parametrize('states,expected',[(['VIOLATED','SATISFIED'],'FAIL'),(['UNKNOWN','SATISFIED'],'INCONCLUSIVE'),(['UNKNOWN','VIOLATED'],'FAIL'),(['UNKNOWN','UNKNOWN'],'INCONCLUSIVE')])
def test_verdict_derivation(env,states,expected):
    vm,c=env;a=copy.deepcopy(ANSWER)
    for f,s in zip(a['findings'],states):
        f['state']=s
        if s=='UNKNOWN':f['source']=-1;f['quote']=''
    prepare(vm,c,answer=a);c.evaluate('case-good');assert result(c)['verdict']==expected

@pytest.mark.parametrize('raw,status,expected,error',[('{}',200,'0'*64,'HASH_MISMATCH'),('x'*16001,200,None,'EVIDENCE_TOO_LARGE'),('{}',404,None,'HTTP_ERROR'),('not JSON',200,None,'MALFORMED_EVIDENCE'),('{"x":1,"x":2}',200,None,'MALFORMED_EVIDENCE')])
def test_integrity(env,raw,status,expected,error):
    vm,c=env;prepare(vm,c,raw=raw,status=status,expected=expected);c.evaluate('case-good')
    assert result(c)=={'verdict':'INCONCLUSIVE','error':error,'findings':[]};assert vm.run_validator()

@pytest.mark.parametrize('field,value',[('assessment_id','other'),('policy_sha256','2'*64),('subject','wrong'),('period','wrong'),('sources',[]),('synthetic','yes'),('schema','other')])
def test_bundle_binding(env,field,value):
    vm,c=env;b=copy.deepcopy(BUNDLE);b[field]=value;prepare(vm,c,bundle=b);c.evaluate('case-good');assert result(c)['error']=='MALFORMED_EVIDENCE'

def test_source_hash(env):
    vm,c=env;prepare(vm,c,doc='modified');c.evaluate('case-good');assert result(c)['error']=='HASH_MISMATCH'

@pytest.mark.parametrize('mutation',['missing','duplicate','state','quote','source','extra','unknown'])
def test_malformed_model_is_retryable(env,mutation):
    vm,c=env;a=copy.deepcopy(ANSWER)
    if mutation=='missing':a['findings'].pop()
    elif mutation=='duplicate':a['findings'][1]=a['findings'][0]
    elif mutation=='state':a['findings'][0]['state']='PASS'
    elif mutation=='quote':a['findings'][0]['quote']='fabricated quote'
    elif mutation=='source':a['findings'][0]['source']=True
    elif mutation=='extra':a['extra']='approve'
    else:a['findings'][0]['state']='UNKNOWN'
    prepare(vm,c,answer=a)
    with vm.expect_revert('Temporary failure'):c.evaluate('case-good')
    assert state(c)['history']==[]

def test_retrieval_failure_retry_same_commit(env):
    vm,c=env;prepare(vm,c,status=503)
    with vm.expect_revert('Temporary failure'):c.evaluate('case-good')
    assert state(c)['revision']==1 and state(c)['history']==[]
    vm.clear_mocks();vm.mock_web(re.escape(URL),{'status':200,'body':C(BUNDLE)});vm.mock_web(re.escape(SOURCE),{'status':200,'body':DOC});vm.mock_llm('operational policy evidence assessor',C(ANSWER))
    c.evaluate('case-good');assert result(c)['verdict']=='PASS'

def test_validator_reexecutes_sources_and_model(env):
    vm,c=env;prepare(vm,c);c.evaluate('case-good');vm.clear_mocks()
    vm.mock_web(re.escape(URL),{'status':200,'body':C(BUNDLE)});vm.mock_web(re.escape(SOURCE),{'status':200,'body':'changed'})
    assert not vm.run_validator()
    vm.clear_mocks();vm.mock_web(re.escape(URL),{'status':200,'body':C(BUNDLE)});vm.mock_web(re.escape(SOURCE),{'status':200,'body':DOC})
    a=copy.deepcopy(ANSWER);a['findings'][0]['state']='VIOLATED';vm.mock_llm('operational policy evidence assessor',C(a));assert not vm.run_validator()

@pytest.mark.parametrize('url',['http://127.0.0.1/a.json','https://example.com/a.json',URL.replace('1'*40,'main'),URL+'?a=1',URL.replace('/evidence/','/../'),URL.replace('https://','https://user@')])
def test_url_restriction(env,url):
    vm,c=env
    with vm.expect_revert('Unsafe'):c.submit_assessment('incident','bad','subject','period',url,'1'*64)

def test_access_and_cross_account_submission(env):
    vm,c=env;prepare(vm,c)
    vm.sender='0x'+'b'*40
    with vm.expect_revert('Only assessment owner'):c.revise_evidence('case-good',URL,'3'*64)
    with vm.expect_revert('Account not admitted'):c.submit_assessment('incident','other','s','p',URL,'1'*64)
    c.evaluate('case-good');assert result(c)['verdict']=='PASS'
    with vm.expect_revert('Only capacity administrator'):c.configure_account(vm.sender,1,1)
    vm.sender='0x'+'a'*40;c.configure_account('0x'+'b'*40,1,1)
    vm.sender='0x'+'b'*40;c.submit_assessment('incident','other','s','p',URL,'1'*64)
    assert json.loads(c.get_assessment('other'))['owner']=='0x'+'b'*40

def test_history_boundaries(env):
    vm,c=env;prepare(vm,c,expected='0'*64);c.evaluate('case-good');old=copy.deepcopy(state(c)['history'])
    with vm.expect_revert('Revision already reviewed'):c.evaluate('case-good')
    with vm.expect_revert('Evidence already reviewed'):c.revise_evidence('case-good',URL,'0'*64)
    c.revise_evidence('case-good',URL,'2'*64);assert state(c)['history']==old
    with vm.expect_revert('Evaluate first'):c.revise_evidence('case-good',URL,'3'*64)
    c.evaluate('case-good');c.revise_evidence('case-good',URL,'3'*64);c.evaluate('case-good')
    assert len(state(c)['history'])==3
    with vm.expect_revert('revision limit'):c.revise_evidence('case-good',URL,'4'*64)

def test_policy_immutable_and_reserved_capacity(env):
    vm,c=env
    with vm.expect_revert('Duplicate policy'):c.create_policy('incident',C(POLICY))
    with vm.expect_revert('Cannot reclaim'):c.configure_account('0x'+'a'*40,0,0)
    with vm.expect_revert('Global reservation'):c.configure_account('0x'+'b'*40,128,128)
    assert json.loads(c.get_capacity('0x'+'a'*40))['account']['used_policies']==1

@pytest.mark.parametrize('mutation',['duplicate','empty','oversize','extra'])
def test_invalid_policy(env,mutation):
    vm,c=env;p=copy.deepcopy(POLICY)
    if mutation=='duplicate':p['criteria']*=2
    elif mutation=='empty':p['criteria']=[]
    elif mutation=='oversize':p['criteria'][0]['requirement']='x'*501
    else:p['extra']='x'
    with vm.expect_revert():c.create_policy('bad',C(p))


def test_multiple_verbatim_excerpts_without_invented_text(env):
    vm,c=env;a=copy.deepcopy(ANSWER)
    a['findings'][1]['quote']='INC-42 detected at 09:00 UTC on 2026-10-01.\nCustomer notice published at 09:40 UTC.'
    prepare(vm,c,answer=a);c.evaluate('case-good');assert result(c)['verdict']=='PASS';assert vm.run_validator()

@pytest.mark.parametrize('quote',['Customer notice published at 09:40 UTC.\nINC-42 detected at 09:00 UTC on 2026-10-01.', 'INC-42 detected at 09:00 UTC on 2026-10-01.\nFabricated notice at 09:40 UTC.', 'INC-42 detected at 09:00 UTC on 2026-10-01. ... Customer notice published at 09:40 UTC.'])
def test_excerpt_grounding_rejects_reordering_fabrication_and_ellipsis(env,quote):
    vm,c=env;a=copy.deepcopy(ANSWER);a['findings'][1]['quote']=quote;prepare(vm,c,answer=a)
    with vm.expect_revert('Temporary failure'):c.evaluate('case-good')
