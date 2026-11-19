# Juniper House demo ideas

The first five are ranked by how much a visitor can learn from one interaction, the evidence already available, and the work required. Each proposed exhibit has a replay or receipt that can settle its main claim.

## First five

1. **Four synchronized viewpoints.** Play one encounter from the porch, garden and driveway while a fourth camera orbits the same 3D scene. One video decoder keeps all four frames together on a phone. Implemented.

2. **A missing feed and a quiet feed.** Remove a bounded interval from a second recording of the same delivery and show what each camera can still support. It makes the difference between silence and missing evidence visible in seconds. `fss-juniper-gap-replay-lceyi`.

3. **Which frames got a model pass?** Stop on a camera-wall frame to see what YOLOX returned and which cameras skipped inference. A single step makes the cost of sparse sampling visible. Implemented.

4. **A roof-down property view.** Jump from the orbit to an overhead plan to see how camera directions and measured entries relate to the house. The same 3D geometry serves the interactive scene and the illustrated field guide. Implemented.

5. **Return to a changed case.** Give two agents the same initial handoff, then add one authorized observation between the two resumes. Visitors see exactly what remains usable and what needs a fresh read. `fss-juniper-handoff-1nhpn`.

## Ten further exhibits

6. **Two clocks at the doorstep.** Advance the recorded capture clock in explicit fixture steps while preserving the camera pixels. Distinguish clock error from apparent motion without changing a live policy. `fss-juniper-clock-4l5oi`.

7. **A private evidence export.** Slide between the original synthetic porch frame and a genuinely masked export. Show which bytes and permissions the receiving agent gets. `fss-juniper-mask-ephhs`.

8. **Line up the survey marks.** Pick an authored point on the ground in two views. Project it onto the metric twin and draw the residual before and after a deliberately perturbed calibration. `fss-juniper-calibration-rr6mg`.

9. **Pause an archive publication.** Stop after the first child object, then resume the archive. Visitors see why an incomplete object set cannot support a visible event root. `fss-juniper-archive-iy2pq`.

10. **Spend one evidence read.** Offer the summary, one camera frame, and its full receipt with their measured byte costs. Let the visitor pick a read under a fixed budget. `fss-juniper-cost-uwykb`.

11. **Buy a second inference.** Run the same film under two fixed inference budgets. Show the additional frame, compute and result the larger budget actually buys. `fss-juniper-budget-fio70`.

12. **Follow a notification receipt.** Follow one eligible synthetic notification into an isolated local relay. Compare duplicate approval and ambiguous acknowledgement next to the existing held event. `fss-juniper-relay-2gwac`.

13. **Review a night in three moments.** Make a short morning digest across the three Juniper encounters. Let a reader open each statement at its source time and see a camera gap from the dropout exhibit. `fss-juniper-night-yknga`.

14. **Print the property contact sheet.** Render a printable sheet with a site plan and the three cameras at a selected time. It gives someone away from the 3D app a reproducible view. `fss-juniper-sheet-n6jcv`.

15. **Why the raccoon went unclassified.** Pair the garden animal's scripted path with its actual foreground and model results. Let a visitor advance to the best available record of the animal without guessing its class. `fss-juniper-wildlife-y9xtp`.

## A second series for the courtyard and optical bench

I compared thirty candidates against the available camera films, deterministic geometry, native reports, cost of generating a repeatable fixture and what a visitor can learn in one interaction. The following five offer the strongest combination.

1. **Two marks locate one ball.** Place the two marks, then remove one. The second camera turns a ray into a position estimate, and an inaccurate mark gives an observable reprojection error. This uses the actual courtyard camera matrices and the native reconstruction binary. The full experiment fits on a phone. Shipped in the stereo bench. `fss-juniper-stereo-y6je0`
2. **See through a longer shutter.** Integrate several samples of the moving hands and ball across a short or long exposure. Holding the trajectory constant isolates motion blur, and projected ball travel gives the renderer an independent check. `fss-juniper-shutter-aa6ei`
3. **Replay a missing view.** Compare a quiet camera with a precisely bounded gap in a second recording. It answers a practical monitoring question in one glance, and the original import plus coverage record can settle what was observable. Reuse `fss-juniper-gap-replay-lceyi`.
4. **See the uncertainty around a point.** Draw the native estimate’s pixel-noise covariance in the same space as the ball. Actual size and clearly labelled magnification make the uncertainty visible without presenting it as total physical error. The new stereo bench supplies the cameras and native matrices. `fss-juniper-ellipse-bnh91`
5. **Compare two performances of the same pass.** Match the earlier and current garden frames at 1.75 seconds. Visitors can inspect the earlier bicycle proposal beside the changed arm poses, then look up each take’s detector decisions. Both films already exist. `fss-juniper-takes-o6wcn`

### Ten more experiments

| Rank | Interaction | What it reveals | Work item |
|---|---|---|---|
| 6 | Superimpose six poses from a single pass | A chronophotograph shows release, floor contact and catch even with playback paused. | `fss-juniper-strobes-jz7aw` |
| 7 | Advance one camera clock | Identical pixels can support a different association when the capture intervals shift. | `fss-juniper-clock-4l5oi` |
| 8 | Change the image resolution | A native report beside the enlarged source pixels shows which proposals survived each supported input mode. | `fss-juniper-resolution-ymlh3` |
| 9 | Compare three court surfaces | Holding the body and release fixed isolates the physical effect of restitution. | `fss-juniper-surfaces-bu5lh` |
| 10 | Re-survey a known point | A deliberately perturbed camera pose makes calibration error measurable in the site view. | `fss-juniper-calibration-rr6mg` |
| 11 | Mask a synthetic frame before export | Opening the actual derivative lets a visitor inspect the pixels an agent receives. | `fss-juniper-mask-ephhs` |
| 12 | Spend a second model inference | Side-by-side native runs show the frame and result purchased by a larger budget. | `fss-juniper-budget-fio70` |
| 13 | Open the poster room | Each exhibit gets a downloadable cover in both social formats, with direct access to its source exhibit. Shipped. | `fss-juniper-posters-uxu8s` |
| 14 | Inspect the raccoon’s best frame | Pair the authored animal identity with the raw garden observations so the model's silence is visible. | `fss-juniper-wildlife-y9xtp` |
| 15 | Print the property contact sheet | A pinned time and site plan let a reader compare the true camera frames away from the live 3D app. | `fss-juniper-sheet-n6jcv` |
