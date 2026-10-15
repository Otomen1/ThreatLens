import { expect, test, type Page } from "@playwright/test";
import { mockOwnerSignIn, OWNER } from "./owner-auth";

const OTHER="00000000-0000-4000-8000-000000000002";
async function identityMocks(page: Page) {
  await page.route("**/api/v1/identity",(route)=>route.fulfill({json:{enabled:true,providers:[],status:"ready",message:"Fixture",framework_version:"1",providers_registered:0,summary:null}}));
  await page.route("**/api/v1/identity/email/check",(route)=>{
    const email=route.request().postDataJSON().email;
    const checked=new Date().toISOString();
    return route.fulfill({json:{checked_at:checked,cache_status:"miss",summary:{entity_type:"email",entity_value:email,
      findings:[{provider:"hibp",provider_display_name:"Have I Been Pwned",status:"not_found",error:null,summary:"No records",evidence:[],fetched_at:checked}],
      statistics:{providers_queried:1,providers_ok:1,total_findings:0,total_assets:0,categories:[]},metadata:{generated_at:checked,framework_version:"1"}}}});
  });
}
async function history(page: Page) {
  return page.evaluate(()=>new Promise<Array<{ownerId:string;email:string}>>((resolve,reject)=>{
    const request=indexedDB.open("threatlens-identity",2);
    request.onsuccess=()=>{const db=request.result; if(!db.objectStoreNames.contains("email-checks")){db.close();resolve([]);return;}
      const read=db.transaction("email-checks").objectStore("email-checks").getAll();read.onsuccess=()=>{db.close();resolve(read.result);};read.onerror=()=>reject(read.error);};
    request.onerror=()=>reject(request.error);
  }));
}

test("signed-out and non-owner visitors cannot load identity data",async({page})=>{
  let calls=0; await page.route("**/api/v1/identity**",route=>{calls++;return route.abort();});
  await page.goto("/identity");await expect(page.getByText("Sign in to access your private workspace.")).toBeVisible();expect(calls).toBe(0);
  await mockOwnerSignIn(page,OTHER);
  await page.route("**/api/v1/auth/me",route=>route.fulfill({status:403,json:{detail:"Owner-only"}}));
  await page.reload();await expect(page.getByText("This workspace is restricted to its owner.")).toBeVisible();expect(calls).toBe(0);
});

test("owner email history survives sign-out but is hidden from another account",async({page})=>{
  await mockOwnerSignIn(page);await identityMocks(page);await page.goto("/identity");
  await page.getByLabel("Email address").fill("owner@example.test");await page.getByRole("button",{name:"Check email",exact:true}).click();
  await expect(page.getByText("Identity check completed.")).toBeVisible();
  expect(await history(page)).toMatchObject([{ownerId:OWNER,email:"owner@example.test"}]);
  await page.getByRole("button",{name:"Sign out",exact:true}).click();
  await expect(page).toHaveURL("http://localhost:31987/");expect(await history(page)).toHaveLength(1);
  await mockOwnerSignIn(page,OTHER);await page.route("**/api/v1/auth/me",route=>route.fulfill({status:403,json:{}}));await page.goto("/identity");
  await expect(page.getByText("This workspace is restricted to its owner.")).toBeVisible();await expect(page.getByLabel("Email address")).toHaveCount(0);
  expect(await history(page)).toMatchObject([{ownerId:OWNER}]);
  await mockOwnerSignIn(page);await page.reload();await page.getByLabel("Email address").fill("owner@example.test");await page.getByRole("button",{name:"Check email",exact:true}).click();
  await expect(page.getByText("+0 since last check")).toBeVisible();
});

test("sign-out rejects a late email lookup without writing history",async({page})=>{
  await mockOwnerSignIn(page);await identityMocks(page);
  let finish!:()=>void;const pending=new Promise<void>(resolve=>{finish=resolve;});
  await page.route("**/api/v1/identity/email/check",async route=>{await pending;await route.fulfill({json:{checked_at:new Date().toISOString(),cache_status:"miss",summary:{findings:[]}}}).catch(()=>undefined);});
  await page.goto("/identity");await page.getByLabel("Email address").fill("late@example.test");await page.getByRole("button",{name:"Check email",exact:true}).click();
  await expect(page.getByRole("button",{name:"Checking…",exact:true})).toBeVisible();
  await page.getByRole("button",{name:"Sign out",exact:true}).click();await expect(page).toHaveURL("http://localhost:31987/");finish();
  expect(await history(page)).toHaveLength(0);
});

test("legacy history requires confirmation and local deletion stays account-scoped", async ({ page }) => {
  await mockOwnerSignIn(page);
  await page.route("**/api/v1/backup/history", route => route.fulfill({ json: { entries: [] } }));
  await page.route("**/api/v1/threat-feed/sources", route => route.fulfill({ json: [] }));
  await page.route("**/api/v1/threat-feed/ioc-sources", route => route.fulfill({ json: [] }));
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Sign out", exact: true })).toBeVisible();
  await page.evaluate(async ({ owner, other }) => {
    const open = (name: string, store: string, keyPath?: string) => new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open(name, 2);
      request.onupgradeneeded = () => {
        const target = request.result.objectStoreNames.contains(store) ? request.transaction!.objectStore(store) : request.result.createObjectStore(store, keyPath ? { keyPath } : undefined);
        if (keyPath && !target.indexNames.contains("owner")) target.createIndex("owner", "ownerId");
      };
      request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
    });
    const batch = await open("threatlens-personal", "batch-sessions");
    await new Promise<void>((resolve, reject) => {
      const tx = batch.transaction("batch-sessions", "readwrite");
      const value = { savedAt: Date.now(), preview: { entities: [] }, rows: [], options: { scanMode: "standard" } };
      tx.objectStore("batch-sessions").put(value, "latest");
      tx.objectStore("batch-sessions").put(value, `owner:${other}`);
      tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error);
    }); batch.close();
    const identity = await open("threatlens-identity", "email-checks", "id");
    // The application creates/upgrades its owner index before opening Settings.
    await new Promise<void>((resolve, reject) => {
      const tx = identity.transaction("email-checks", "readwrite"); const checked = new Date().toISOString();
      const response = { checked_at: checked, cache_status: "miss", summary: { entity_value: "legacy@example.test", findings: [], statistics: {}, metadata: {} } };
      tx.objectStore("email-checks").put({ id: "legacy", email: "legacy@example.test", checkedAt: checked, response });
      tx.objectStore("email-checks").put({ id: "other", ownerId: other, email: "other@example.test", checkedAt: checked, response });
      tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error);
    }); identity.close();
    localStorage.setItem("unrelated-preference", "keep");
    void owner;
  }, { owner: OWNER, other: OTHER });
  await page.goto("/settings");
  await expect(page.getByText(/Older unscoped browser records exist/)).toBeVisible();
  expect((await history(page)).some(record => record.ownerId === OWNER)).toBe(false);
  await page.getByRole("button", { name: "Import my legacy history" }).click();
  expect((await history(page)).some(record => record.ownerId === OWNER)).toBe(false);
  await page.getByRole("button", { name: "Confirm legacy import" }).click();
  await expect(page.getByText("Valid legacy records imported into your account partition.")).toBeVisible();
  expect(await history(page)).toHaveLength(2);
  expect((await history(page)).some(record => record.ownerId === OWNER)).toBe(true);
  await page.getByRole("button", { name: "Delete local identity history", exact: true }).click();
  await page.getByRole("button", { name: "Confirm local deletion" }).click();
  await expect(page.getByText("Selected local records deleted. Other data is unchanged.")).toBeVisible();
  expect(await history(page)).toMatchObject([{ ownerId: OTHER }]);
  await page.getByRole("button", { name: "Delete local batch recovery", exact: true }).click();
  await page.getByRole("button", { name: "Confirm local deletion" }).click();
  await expect.poll(() => page.evaluate(() => new Promise<IDBValidKey[]>((resolve) => {
    const request = indexedDB.open("threatlens-personal", 2); request.onsuccess = () => {
      const db = request.result; const tx = db.transaction("batch-sessions"); const read = tx.objectStore("batch-sessions").getAllKeys();
      tx.oncomplete = () => { db.close(); resolve(read.result); };
    };
  }))).toEqual([`owner:${OTHER}`]);
  expect(await page.evaluate(() => localStorage.getItem("unrelated-preference"))).toBe("keep");
});

test("history limits and expired batch recovery are enforced on read", async ({ page }) => {
  await mockOwnerSignIn(page); await identityMocks(page); await page.goto("/identity");
  await expect(page.getByLabel("Email address")).toBeVisible();
  await page.evaluate(async owner => {
    await new Promise<void>((resolve) => {
      const request = indexedDB.open("threatlens-identity", 2);
      request.onupgradeneeded = () => request.result.createObjectStore("email-checks", { keyPath: "id" }).createIndex("owner", "ownerId");
      request.onsuccess = () => {
        const db = request.result; const tx = db.transaction("email-checks", "readwrite"); const store = tx.objectStore("email-checks");
        for (let i = 0; i < 24; i++) {
          const checked = new Date(Date.now() - (i < 23 ? i * 1000 : 91 * 86400000)).toISOString();
          store.put({ id: `fixture-${i}`, ownerId: owner, email: "owner@example.test", checkedAt: checked, response: { checked_at: checked, cache_status: "miss", summary: { entity_value: "owner@example.test", findings: [], statistics: {}, metadata: {} } } });
        }
        store.put({ id: "corrupt", ownerId: owner });
        tx.oncomplete = () => { db.close(); resolve(); };
      };
    });
    await new Promise<void>((resolve) => {
      const request = indexedDB.open("threatlens-personal", 2);
      request.onupgradeneeded = () => request.result.createObjectStore("batch-sessions");
      request.onsuccess = () => {
        const db = request.result; const tx = db.transaction("batch-sessions", "readwrite");
        tx.objectStore("batch-sessions").put({ savedAt: Date.now() - 25 * 3600000, preview: { entities: [] }, rows: [], options: {} }, `owner:${owner}`);
        tx.oncomplete = () => { db.close(); resolve(); };
      };
    });
  }, OWNER);
  await page.getByLabel("Email address").fill("owner@example.test");
  await page.getByRole("button", { name: "Check email", exact: true }).click();
  await expect(page.getByText("Identity check completed.")).toBeVisible();
  expect(await history(page)).toHaveLength(20);
  await page.goto("/"); await expect(page.getByRole("button", { name: "Sign out", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Resume previous batch" })).toHaveCount(0);
  await expect.poll(() => page.evaluate(() => new Promise<number>((resolve) => {
    const request = indexedDB.open("threatlens-personal", 2); request.onsuccess = () => {
      const db = request.result; const tx = db.transaction("batch-sessions"); const read = tx.objectStore("batch-sessions").count();
      tx.oncomplete = () => { db.close(); resolve(read.result); };
    };
  }))).toBe(0);
});
