import { afterEach, describe, expect, it } from "vitest";
import { assertPrivateOwner, invalidatePrivateSession, privateGeneration, privateOwner, setPrivateOwner, trackPrivateRequest } from "./privateSession";
import { validBatchSession } from "./batchSession";
import { validIdentityHistory } from "./identityHistory";
const owner="00000000-0000-4000-8000-000000000001";
afterEach(()=>setPrivateOwner(null));
describe("private session boundary",()=>{
  it("requires the verified identity, aborts work, and clears only memory",()=>{
    expect(()=>assertPrivateOwner(owner)).toThrow(); setPrivateOwner(owner); assertPrivateOwner(owner);
    const controller=new AbortController(); const clean=trackPrivateRequest(controller); const before=privateGeneration();
    setPrivateOwner(null); expect(controller.signal.aborted).toBe(true); expect(privateOwner()).toBeNull(); expect(privateGeneration()).toBeGreaterThan(before); clean();
  });
  it("invalidates pending work before owner verification finishes",()=>{
    const controller=new AbortController(); trackPrivateRequest(controller); invalidatePrivateSession(); expect(controller.signal.aborted).toBe(true);
  });
  it("rejects corrupt or expired local records",()=>{
    expect(validBatchSession({})).toBe(false); expect(validIdentityHistory({})).toBe(false);
    const record={id:"fixture",email:"owner@example.test",checkedAt:new Date(Date.now()-91*86400000).toISOString(),response:{summary:{findings:[]}}};
    expect(validIdentityHistory(record)).toBe(false);
    expect(validBatchSession({savedAt:Date.now()-25*3600000,preview:{entities:[]},rows:[],options:{scanMode:"standard"}})).toBe(false);
  });
});
