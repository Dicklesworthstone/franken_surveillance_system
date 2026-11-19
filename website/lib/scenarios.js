// All coordinates are metres in one fictional, owner-controlled property.
export const DURATION = 12;
export const cameras = [
  { id: "porch", label: "Porch", position: [-3.7, 3.1, 2.3], target: [-0.9, 1, 6.0], fov: 71 },
  { id: "garden", label: "Garden", position: [-4.9, 2.7, -2.2], target: [-7.3, 0.4, 3.2], fov: 75 },
  { id: "drive", label: "Driveway", position: [6.6, 3.0, 1.8], target: [3.3, 0.9, 7.0], fov: 70 },
];
export const cases = [
  { id: "delivery", title: "The doorstep delivery", short: "Delivery", camera: "porch", subject: "Parcel courier", kind: "Person", time: "17:42", color: "#d8f47b",
    detail: "A courier carries a parcel from the sidewalk to the front steps.", action: "Parcel reaches the porch", zone: "Front porch", zoneBounds: [-2.9, 0.8, 1.8, 4.3],
    path: [[0,0,9.1],[3,-0.8,6.9],[7,-1.55,3.0],[9,-1.55,3.0],[12,-0.6,6.7]] },
  { id: "wildlife", title: "A visitor in the garden", short: "Wildlife", camera: "garden", subject: "Raccoon", kind: "Animal", time: "21:16", color: "#a4d7d4",
    detail: "A raccoon pauses beside the bins and moves back across the lawn.", action: "Animal reaches the bins", zone: "Garden bins", zoneBounds: [-8.5,-5.4,0.4,3.6],
    path: [[0,-8.9,6.8],[3,-8.1,4.6],[6.6,-6.8,1.8],[8.7,-6.8,1.8],[12,-8.4,5.5]] },
  { id: "visitor", title: "An after-hours arrival", short: "Perimeter", camera: "drive", subject: "Unknown visitor", kind: "Person", time: "23:08", color: "#ffbc86",
    detail: "A simulated intruder crosses the driveway boundary. The camera can establish a person crossing, while intent stays unknown.", action: "Person crosses the driveway zone", zone: "Driveway approach", zoneBounds: [1.8,4.7,3.0,6.1],
    path: [[0,7.8,8.9],[3,5.6,7.7],[7,3.15,5.0],[9,2.8,4.0],[12,1.0,6.9]] },
];
export function subjectAt(scenario, time) {
  const points = scenario.path;
  const end = points.findIndex((p,i) => i > 0 && p[0] >= time);
  const [a,b] = end < 0 ? points.slice(-2) : [points[end-1], points[end]];
  const f = Math.max(0,Math.min(1,(time-a[0])/(b[0]-a[0])));
  const x=a[1]+(b[1]-a[1])*f, z=a[2]+(b[2]-a[2])*f;
  const [left,right,near,far]=scenario.zoneBounds;
  return {x,z,yaw:Math.atan2(b[1]-a[1],b[2]-a[2]), moving:a[1]!==b[1]||a[2]!==b[2], inZone:x>=left&&x<=right&&z>=near&&z<=far};
}
export function stamp(seconds) {return '00:'+Math.floor(seconds).toString().padStart(2,'0');}
