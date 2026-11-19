import assert from "node:assert/strict";
export async function checkStereoUI(browser,origin){
 for(const width of [1280,390,320]){
  const page=await browser.newPage({viewport:{width,height:900},reducedMotion:"reduce"});
  const errors=[];page.on("pageerror",e=>errors.push(e.message));
  if(width===320)await page.route("**/court/receiver.glb",r=>r.abort());
  await page.goto(origin);
  await page.locator(".cover-index button").filter({hasText:"Stereo bench"}).click();
  await page.getByRole("link",{name:"Open the stereo bench"}).click();
  await page.locator('[data-court-state="'+(width===320?"diagram":"webgl")+'"]').waitFor();
  const state=page.locator("[data-stereo-state]");
  const get=async()=>state.getAttribute("data-stereo-state");
  assert.equal(await get(),"fit");
  await page.getByRole("button",{name:"Clear patio mark"}).click();assert.equal(await get(),"waiting");
  const frame=page.getByRole("button",{name:"Mark ball in Patio frame"});
  await frame.click({position:{x:10,y:10}});assert.notEqual(await get(),"fit");
  await page.getByRole("button",{name:"Restore reference marks"}).click();assert.equal(await get(),"fit");
  await frame.press("ArrowRight");await page.getByText("Your marks",{exact:true}).waitFor();assert.equal(await get(),"fit");
  await page.getByRole("button",{name:/Near the floor/}).click();
  const link=page.getByRole("link",{name:/Read the native result/});assert.equal(await link.getAttribute("href"),"/stereo/report-28.json");
  await page.getByRole("button",{name:/After the bounce/}).click();
  assert.equal(await link.getAttribute("href"),"/stereo/report-38.json");
  await page.getByRole("button",{name:/In flight/}).click();
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  if(process.env.SCREENSHOT_DIR){await page.evaluate(()=>window.scrollTo({top:0,behavior:"instant"}));await page.screenshot({path:process.env.SCREENSHOT_DIR+"/stereo-"+width+".png"});}
  assert.deepEqual(errors,[]);await page.close();
 }
 console.log("Stereo controls, reference recovery, keyboard edits, native reports and missing-asset fallback passed at three widths.");
}
