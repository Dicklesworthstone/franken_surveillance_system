// Sample the simulated camera shutter before JPEG or video compression.
export function cameraFrameReader(stage, canvas, shutterSeconds) {
  const gl = canvas.getContext("webgl2");
  if (!gl || gl.isContextLost())
    throw Error("A working WebGL 2 context is required for camera capture");
  const { width, height } = canvas;
  const copy = document.createElement("canvas");
  copy.width = width;
  copy.height = height;
  const context = copy.getContext("2d", { alpha: false });
  const image = context.createImageData(width, height);
  const output = new Uint32Array(image.data.buffer);
  const taps = Array.from(
    { length: 3 },
    () => new Uint8Array(image.data.length),
  );
  const [early, middle, late] = taps;
  const [earlyPixel, middlePixel, latePixel] = taps.map(
    (tap) => new Uint32Array(tap.buffer),
  );

  // Integrate light rather than averaging gamma-encoded colors at moving edges.
  const linear = Uint16Array.from({ length: 256 }, (_, byte) => {
    const v = byte / 255;
    const light = v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
    return Math.round(65535 * light);
  });
  const srgb = Uint8Array.from({ length: 65536 }, (_, index) => {
    const v = index / 65535;
    const encoded = v <= 0.0031308 ? 12.92 * v : 1.055 * v ** (1 / 2.4) - 0.055;
    return Math.round(255 * encoded);
  });

  return ({ id, t, camera }) => {
    if (gl.drawingBufferWidth !== width || gl.drawingBufferHeight !== height)
      throw Error(
        `Camera buffer changed size during capture of ${id}/${camera}`,
      );
    let sample;
    for (let i = 0; i < taps.length; i++) {
      // Midpoint of each third of the exposure. Hold the opening pose before t=0.
      const instant = Math.max(0, t + ((i - 1) * shutterSeconds) / 3);
      const pose = stage.draw(id, instant, camera);
      if (i === 1) sample = pose;
      gl.finish();
      gl.readPixels(0, 0, width, height, gl.RGBA, gl.UNSIGNED_BYTE, taps[i]);
      const error = gl.getError();
      if (error !== gl.NO_ERROR || gl.isContextLost())
        throw Error(
          `Camera readback failed on ${id}/${camera} at ${instant}s (WebGL ${error})`,
        );
    }
    for (let y = 0; y < height; y++) {
      const row = (height - y - 1) * width;
      for (let x = 0; x < width; x++) {
        const src = row + x;
        const dst = y * width + x;
        output[dst] = middlePixel[src];
        // The fixed architectural plate is identical in the three samples.
        if (
          earlyPixel[src] === middlePixel[src] &&
          middlePixel[src] === latePixel[src]
        )
          continue;
        for (let channel = 0; channel < 3; channel++) {
          const p = src * 4 + channel;
          const mean =
            (linear[early[p]] + linear[middle[p]] + linear[late[p]]) / 3;
          image.data[dst * 4 + channel] = srgb[Math.round(mean)];
        }
      }
    }
    context.putImageData(image, 0, 0);
    return { sample, jpeg: copy.toDataURL("image/jpeg", 0.95).split(",")[1] };
  };
}
