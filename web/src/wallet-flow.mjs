import {verifyWrite} from './safety.mjs';
export function walletError(error){if(error?.code===4001)return 'Wallet request rejected. No completion is confirmed.';return String(error?.message||error);}
export async function sendReviewedWrite({confirmed,provider,account,address,method,args,makeWriter,client,read,status=(_message)=>{}}){
 if(confirmed!==true)throw Error('Explicit transaction confirmation is required.');
 if(!provider)throw Error('No browser wallet provider available.');
 const accounts=await provider.request({method:'eth_accounts'});if(accounts[0]?.toLowerCase()!==account.toLowerCase())throw Error('Account changed. Reconnect and review.');
 if(Number(await provider.request({method:'eth_chainId'}))!==61999)throw Error('Wrong network. Select GenLayer Studionet, chain 61999, RPC https://studio.genlayer.com/api, then review again.');
 const before=['evaluate','revise_evidence'].includes(method)?await read('get_assessment',[args[0]]):undefined;
 const writer=makeWriter({account,provider});status('Waiting for wallet confirmation…');
 const hash=await writer.writeContract({address,functionName:method,args,value:0n,leaderOnly:false});status(`Submitted ${hash}. Waiting for finality and execution verification…`);
 const state=await verifyWrite({client,hash,read,method,args,account,before});return {hash,state};
}
