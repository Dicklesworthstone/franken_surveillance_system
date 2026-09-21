#!/usr/bin/env python3
"""Offline arithmetic comparison; this mirrors a recipe, NOT Rust execution or quality.
Requires preinstalled cv2 4.13.0 and NumPy; performs no network or output-file writes.
"""
import cv2, numpy as np, math, json, hashlib
from pathlib import Path
if cv2.__version__ != "4.13.0":
    raise SystemExit("unpinned oracle")
raw = cv2.HOGDescriptor_getDefaultPeopleDetector().astype("<f4").tobytes()
if hashlib.sha256(raw).hexdigest() != "cb2198952eaa5bc7e43d950b9f2aa1966528063c7295c7262133e7fa0d3d564c":
    raise SystemExit("unexpected oracle weights")
weights=cv2.HOGDescriptor_getDefaultPeopleDetector().astype(np.float64)
# Mirror only the scalar recipe for differential investigation; this is NOT Rust execution.
def features(a):
    h,w=a.shape
    p=np.sqrt(a.astype(np.float64)); xp=np.r_[1,np.arange(w-1)]; xn=np.r_[np.arange(1,w),w-2]
    yp=np.r_[1,np.arange(h-1)]; yn=np.r_[np.arange(1,h),h-2]
    dx=p[:,xn]-p[:,xp];dy=p[yn,:]-p[yp,:]
    m=np.sqrt(dx*dx+dy*dy); t=np.arctan2(dy,dx);t=np.where(t<0,t+math.tau,t)
    pos=t*(9/math.pi)-.5;lo=np.floor(pos);f=pos-lo;bins=lo.astype(np.int32)%9
    votes=[m*(1-f),m*f]
    ix,iy=np.indices((16,16));cx=(ix+.5)/8-.5;cy=(iy+.5)/8-.5
    x0=np.floor(cx).astype(int);y0=np.floor(cy).astype(int);fx=cx-x0;fy=cy-y0
    g=np.exp(-((ix-8)**2+(iy-8)**2)/32)
    weights_cell=[]
    for cellx in range(2):
        for celly in range(2):
            wx=np.where(x0==cellx,1-fx,np.where(x0+1==cellx,fx,0))
            wy=np.where(y0==celly,1-fy,np.where(y0+1==celly,fy,0))
            weights_cell.append(g*wx*wy)
    out=[]
    for bx in range(7):
        for by in range(15):
            x,y=bx*8,by*8
            b=bins[y:y+16,x:x+16].T.ravel()
            vs=[v[y:y+16,x:x+16].T.ravel() for v in votes]
            hist=[]
            for wc in weights_cell:
                wc=wc.ravel()
                # Interleave the two votes so repeated-bin addition order matches the Rust loop.
                bi=np.column_stack((b,(b+1)%9)).ravel()
                vi=np.column_stack((vs[0]*wc,vs[1]*wc)).ravel()
                hist.extend(np.bincount(bi,weights=vi,minlength=9))
            hist=np.array(hist)
            scale=1/(math.sqrt(sum(v*v for v in hist))+3.6)
            hist=np.minimum(hist*scale,.2)
            scale=1/(math.sqrt(sum(v*v for v in hist))+.001)
            out.extend(np.array(hist*scale,dtype=np.float32))
    return np.array(out,np.float32)
def fixture(k):
    y,x=np.indices((128,64),dtype=np.uint32)
    if k==0:return np.zeros((128,64),np.uint8)
    if k==1:return np.full((128,64),255,np.uint8)
    if k==2:return (x*4+0*y).astype(np.uint8)
    if k==3:return (y*2+0*x).astype(np.uint8)
    if k==4:return (((x//8+y//8)%2)*255).astype(np.uint8)
    return ((x*(17+k*2)+y*(31+k*3)+(x*y)%(13+k*5))%256).astype(np.uint8)
h=cv2.HOGDescriptor(); print('gamma',h.gammaCorrection,'sigma',h.getWinSigma())
results=[]
for k in range(64):
    a=fixture(k); ref=h.compute(a).ravel(); native=features(a)
    s=lambda f: float(sum(float(a)*float(b) for a,b in zip(f,weights[:-1]))+weights[-1])
    results.append({'fixture':k,'native_score':s(native),'opencv_score':s(ref),'max_feature_delta':float(np.max(np.abs(native-ref)))})
print(json.dumps(results[:10],indent=2))
print('max score error',max(abs(r['native_score']-r['opencv_score']) for r in results),'max feature',max(r['max_feature_delta'] for r in results))
retained = json.loads((Path(__file__).resolve().parents[1] / "crates/fss-twin/models/opencv_people/numeric_smoke.json").read_text())
if len(retained) != len(results):
    raise SystemExit("fixture set differs")
for actual, old in zip(results, retained):
    if actual["fixture"] != old["fixture"] or abs(actual["native_score"]-old["native_score"]) > 2e-6 or abs(actual["opencv_score"]-old["opencv_score"]) > 0.003:
        raise SystemExit("retained numeric example differs; investigate, do not rewrite pins")
print("64 supplementary arithmetic cases matched; no Rust execution or model-quality claim")
